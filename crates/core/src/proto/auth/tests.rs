//! Spec 031-auth-channel-signature: the signed message, the `channel_id`
//! and the check of a `subscribe`, against `031.json` and as a round trip
//! with the `subscribe` the session builds (spec 028-session-sans-io R6).

use proptest::prelude::*;

use super::{AUTH_TAG, auth_message};
use crate::Error;
use crate::crypto::Secret;
use crate::proto::config::{ChannelId, Config};
use crate::relay;
use crate::session::channel::Channel;
use crate::session::connection::subscribe;
use crate::session::frames::Frame;
use crate::storage::Vault;
use crate::testing::MemoryVault;
use crate::vectors::{self, Checker, Kind, Vector};

/// What the server reads from a vector's `subscribe`.
struct Sent {
    server_url: String,
    pk_ch: [u8; 32],
    ttl_seconds: u32,
    sig: [u8; 64],
    server_nonce: [u8; 32],
}

fn sent(vector: &Vector) -> Sent {
    Sent {
        server_url: String::from_utf8(vector.input("server_url").bytes().to_vec()).unwrap(),
        pk_ch: vector.input("pk_ch").array(),
        ttl_seconds: vector.input("ttl_seconds").number(),
        sig: vector.input("sig").array(),
        server_nonce: vector.input("server_nonce").array(),
    }
}

/// `verify_subscribe` with the one host of the vector's URL.
fn verify(sent: &Sent) -> Result<[u8; 16], Error> {
    let hosts = [relay::url_host(&sent.server_url).unwrap()];
    relay::verify_subscribe(
        &sent.pk_ch,
        sent.ttl_seconds,
        &sent.sig,
        &sent.server_nonce,
        &hosts,
    )
}

/// The config of a positive vector, and the `subscribe` the session builds
/// for it under the vector's nonce.
fn session_subscribe(
    k_ch: [u8; 32],
    server_url: &str,
    ttl_seconds: u32,
    nonce: &[u8; 32],
) -> (Config, Frame) {
    let config =
        Config::from_parts(Secret::from_bytes(k_ch), server_url, ttl_seconds, "room", 0).unwrap();
    let store = MemoryVault::new().create(&config.channel_id()).unwrap();
    let (channel, _) = Channel::create(&config, store).unwrap();
    let frame = Frame::decode(&subscribe(&channel, nonce).unwrap()).unwrap();
    (config, frame)
}

/// The error a negative vector names.
fn error_of(vector: &Vector) -> Option<Error> {
    match vector.expected("error").text() {
        "BadSignature" => Some(Error::BadSignature),
        "BadConfig" => Some(Error::BadConfig),
        _ => None,
    }
}

fn check_positive(vector: &Vector) {
    let sent = sent(vector);
    let channel_id: [u8; 16] = vector.expected("channel_id").array();
    let host = String::from_utf8(vector.expected("host").bytes().to_vec()).unwrap();
    assert_eq!(relay::url_host(&sent.server_url).unwrap(), host);
    let message = auth_message(
        &sent.server_nonce,
        &ChannelId(channel_id),
        sent.ttl_seconds,
        &host,
    );
    assert_eq!(message, vector.expected("message").bytes());
    assert_eq!(
        relay::channel_id(&sent.pk_ch, sent.ttl_seconds),
        Ok(channel_id)
    );
    assert_eq!(verify(&sent), Ok(channel_id));

    // The client signs the same bytes: Ed25519 is deterministic, so the
    // session's `subscribe` carries the vector's signature.
    let k_ch = vector.input("k_ch").array();
    let (config, frame) =
        session_subscribe(k_ch, &sent.server_url, sent.ttl_seconds, &sent.server_nonce);
    assert_eq!(config.channel_id(), channel_id);
    assert!(matches!(
        frame,
        Frame::Subscribe { pk_ch, ttl_seconds, sig, .. }
            if pk_ch == sent.pk_ch && ttl_seconds == sent.ttl_seconds && sig == sent.sig
    ));
}

fn check_negative(vector: &Vector) {
    let sent = sent(vector);
    assert_eq!(verify(&sent).err(), error_of(vector), "{}", vector.name());
    // The server names the channel in its answer, whatever the error.
    assert_eq!(
        relay::channel_id(&sent.pk_ch, sent.ttl_seconds),
        Ok(vector.expected("channel_id").array())
    );
}

fn check_vector(vector: &Vector) {
    match vector.kind() {
        Kind::Positive => check_positive(vector),
        Kind::Negative => check_negative(vector),
    }
}

/// Spec 031, R10: every vector of `031.json`, through `auth_message`,
/// `relay::channel_id` and `verify_subscribe`.
#[test]
fn s031_t10_r10_vectors_reproduced() {
    let names = [
        "auth_reference",
        "auth_url_with_port",
        "auth_onion_ws",
        "auth_ttl_60",
        "auth_ttl_2592000",
        "auth_wrong_host",
        "auth_wrong_nonce",
        "auth_flipped_sig",
        "auth_other_ttl",
        "auth_ttl_59",
        "auth_ttl_2592001",
    ];
    let entries: Vec<(&str, Checker)> = names
        .iter()
        .map(|name| (*name, check_vector as Checker))
        .collect();
    vectors::check_all("031", &entries);
}

/// Spec 031, R2: the tag is the literal of `docs/spec.md` §4, and the
/// reference message is the vector's.
#[test]
fn s031_t02_r02_auth_message() {
    assert_eq!(AUTH_TAG.len(), 19);
    assert_eq!(AUTH_TAG, b"privatechat/auth/v1");
    let reference = vectors::load("031", "auth_reference");
    check_positive(&reference);
    // The port is not signed: the same channel on a URL with a port signs
    // the same bytes.
    let with_port = vectors::load("031", "auth_url_with_port");
    assert_eq!(
        reference.expected("message").bytes(),
        with_port.expected("message").bytes()
    );
    assert_eq!(
        reference.input("sig").bytes(),
        with_port.input("sig").bytes()
    );
}

/// Spec 031, R3: `relay::channel_id` is the config's `channel_id`, and the
/// two ends of the TTL give two.
#[test]
fn s031_t03_r03_channel_id() {
    let short = vectors::load("031", "auth_ttl_60");
    let long = vectors::load("031", "auth_ttl_2592000");
    for vector in [&short, &long] {
        let sent = sent(vector);
        let k_ch = vector.input("k_ch").array();
        let config = Config::from_parts(
            Secret::from_bytes(k_ch),
            &sent.server_url,
            sent.ttl_seconds,
            "room",
            0,
        )
        .unwrap();
        assert_eq!(
            relay::channel_id(&sent.pk_ch, sent.ttl_seconds),
            Ok(config.channel_id())
        );
    }
    assert_ne!(
        short.expected("channel_id").bytes(),
        long.expected("channel_id").bytes()
    );
}

/// Spec 031, R4: the hosts are tried in order, and their number and the TTL
/// are checked before any signature.
#[test]
fn s031_t04_r04_verify_subscribe() {
    let reference = sent(&vectors::load("031", "auth_reference"));
    let id = relay::channel_id(&reference.pk_ch, reference.ttl_seconds).unwrap();
    let host = |name: &str| name.to_owned();
    let third = [
        host("a.example.org"),
        host("b.example.org"),
        host("chat.example.org"),
    ];
    let check = |hosts: &[String]| {
        relay::verify_subscribe(
            &reference.pk_ch,
            reference.ttl_seconds,
            &reference.sig,
            &reference.server_nonce,
            hosts,
        )
    };
    assert_eq!(check(&third), Ok(id));
    assert_eq!(check(&[]), Err(Error::BadConfig));
    let nine: Vec<String> = (0..9).map(|_| host("chat.example.org")).collect();
    assert_eq!(check(&nine), Err(Error::BadConfig));
    assert_eq!(check(&nine[..8]), Ok(id));
    for vector in vectors::all("031")
        .iter()
        .filter(|vector| vector.kind() == Kind::Negative)
    {
        check_negative(vector);
    }
}

/// Spec 031, R8: the host the signature covers is the config's, through the
/// one URL parser.
#[test]
fn s031_t08_r08_url_host() {
    assert_eq!(relay::url_host("wss://h:9001"), Ok("h".to_owned()));
    assert_eq!(
        relay::url_host("wss://chat.example.org"),
        Ok("chat.example.org".to_owned())
    );
    let onion = format!("ws://{}.onion", "a".repeat(56));
    assert_eq!(
        relay::url_host(&onion),
        Ok(format!("{}.onion", "a".repeat(56)))
    );
    for bad in ["wss://h/", "https://h", "wss://h:443", "ws://h", ""] {
        assert_eq!(relay::url_host(bad), Err(Error::BadConfig), "{bad}");
    }
}

/// Spec 031, R1: two nonces differ.
#[test]
fn s031_t01_r01_new_nonce() {
    let first = relay::new_nonce().unwrap();
    let second = relay::new_nonce().unwrap();
    assert_ne!(first, second);
    let same = first.iter().zip(&second).filter(|(a, b)| a == b).count();
    assert!(same < 8, "{same} equal bytes");
}

/// Any URL of the grammar of spec 011 R5.
fn server_urls() -> impl Strategy<Value = String> {
    let port = proptest::option::of(1u16..=65_535);
    let tls = ("[a-z0-9.-]{1,60}", port.clone())
        .prop_filter("no implied port", |(_, port)| *port != Some(443))
        .prop_map(|(host, port)| with_port(format!("wss://{host}"), port));
    let onion = ("[a-z2-7]{56}", port)
        .prop_filter("no implied port", |(_, port)| *port != Some(80))
        .prop_map(|(label, port)| with_port(format!("ws://{label}.onion"), port));
    prop_oneof![tls, onion]
}

fn with_port(url: String, port: Option<u16>) -> String {
    port.map_or(url.clone(), |port| format!("{url}:{port}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 031, R11: the `subscribe` the session builds for any config and
    /// nonce opens that config's channel on the server.
    #[test]
    fn s031_t11_r11_round_trip_and_fuzz(
        k_ch in any::<[u8; 32]>(),
        ttl_seconds in 60u32..=2_592_000,
        nonce in any::<[u8; 32]>(),
        server_url in server_urls(),
    ) {
        let (config, frame) = session_subscribe(k_ch, &server_url, ttl_seconds, &nonce);
        let hosts = [relay::url_host(&server_url).unwrap()];
        let opens = matches!(
            frame,
            Frame::Subscribe { pk_ch, ttl_seconds: sent_ttl, sig, .. }
                if relay::verify_subscribe(&pk_ch, sent_ttl, &sig, &nonce, &hosts)
                    == Ok(config.channel_id())
        );
        prop_assert!(opens);
    }
}
