//! Spec 031-auth-channel-signature, the server half: `AuthState` over a
//! monotonic `now` (spec 032-storage-ttl R14), with no socket. The client's
//! signature comes from `testing::subscribe_credential`, which signs what the
//! session signs; the vectors of `031.json` are signed again under the
//! state's own nonce, which the server draws at random.

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use crate::auth::{AuthState, Verdict};

/// The `k_ch` of every vector of `031.json`.
const K_CH: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const DAY: u32 = 86_400;
const HOST: &str = "chat.example.org";
const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
const VECTORS: &str = include_str!("../../../../specs/vectors/031.json");

fn hosts() -> Vec<String> {
    vec![HOST.to_owned()]
}

fn nonce_of(frame: &Frame) -> [u8; 32] {
    match frame {
        Frame::Hello { server_nonce, .. } => *server_nonce,
        _ => [0; 32],
    }
}

fn versions_of(frame: &Frame) -> Vec<u8> {
    match frame {
        Frame::Hello { proto_versions, .. } => proto_versions.clone(),
        _ => Vec::new(),
    }
}

/// A `subscribe` of the test channel as the server sees it.
struct Subscribe {
    pk_ch: [u8; 32],
    ttl_seconds: u32,
    sig: [u8; 64],
}

/// Signed under `nonce` for `host` at `signing_ttl`, sent with `ttl_seconds`.
fn sent(nonce: &[u8; 32], signing_ttl: u32, ttl_seconds: u32, host: &str) -> Subscribe {
    let (pk_ch, sig) = subscribe_credential(K_CH, signing_ttl, nonce, host).unwrap();
    Subscribe {
        pk_ch,
        ttl_seconds,
        sig,
    }
}

fn signed(nonce: &[u8; 32], host: &str) -> Subscribe {
    sent(nonce, DAY, DAY, host)
}

fn check(state: &mut AuthState, subscribe: &Subscribe, hosts: &[String], now: u64) -> Vec<Verdict> {
    state
        .on_subscribe(
            &subscribe.pk_ch,
            subscribe.ttl_seconds,
            &subscribe.sig,
            hosts,
            now,
        )
        .unwrap()
}

fn channel(ttl_seconds: u32) -> [u8; 16] {
    relay::channel_id(&sent(&[0; 32], DAY, DAY, HOST).pk_ch, ttl_seconds).unwrap()
}

fn is_accept(verdicts: &[Verdict], expected: [u8; 16]) -> bool {
    matches!(verdicts, [Verdict::Accept { channel_id }] if *channel_id == expected)
}

fn is_bad_auth(verdicts: &[Verdict], expected: [u8; 16]) -> bool {
    matches!(verdicts, [Verdict::BadAuth { channel_id }] if *channel_id == expected)
}

/// The nonce of the `hello` a `NonceExpired` carries, if that is the verdict.
fn expired_hello(verdicts: &[Verdict]) -> Option<[u8; 32]> {
    match verdicts {
        [Verdict::NonceExpired { channel_id, hello }] if *channel_id == channel(DAY) => {
            Some(nonce_of(hello))
        }
        _ => None,
    }
}

/// A connection whose first `subscribe` was accepted at 1 ms, so that its
/// first-subscribe deadline no longer applies, and the nonce of its `hello`.
fn accepted() -> (AuthState, [u8; 32]) {
    let (mut state, hello) = AuthState::new(0).unwrap();
    let nonce = nonce_of(&hello);
    assert!(is_accept(
        &check(&mut state, &signed(&nonce, HOST), &hosts(), 1),
        channel(DAY)
    ));
    (state, nonce)
}

/// A string field of the vector `name` of `031.json`, read from the text.
fn vector_field(name: &str, field: &str) -> String {
    let at = VECTORS.find(&format!("\"name\": \"{name}\"")).unwrap();
    let rest = &VECTORS[at..];
    let start = rest.find(&format!("\"{field}\": \"")).unwrap() + field.len() + 5;
    rest[start..start + rest[start..].find('"').unwrap()].to_owned()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn s031_t01_r01_nonce_lifetime() {
    let (_, other) = AuthState::new(0).unwrap();
    let (mut state, hello) = AuthState::new(0).unwrap();
    let first = nonce_of(&hello);
    assert_eq!(versions_of(&hello), [1]);
    assert_ne!(first, [0; 32]);
    assert_ne!(first, nonce_of(&other));
    assert!(is_accept(
        &check(&mut state, &signed(&first, HOST), &hosts(), 59_999),
        channel(DAY)
    ));

    // Valid for 60 000 ms from the hello's own time, not from 0.
    let (mut state, hello) = AuthState::new(1_000).unwrap();
    let verdicts = check(
        &mut state,
        &signed(&nonce_of(&hello), HOST),
        &hosts(),
        61_000,
    );
    assert!(is_accept(&verdicts, channel(DAY)));

    // 60 001 ms after its hello the nonce has expired: a new one comes.
    let (mut state, first) = accepted();
    let verdicts = check(&mut state, &signed(&first, HOST), &hosts(), 60_001);
    let second = expired_hello(&verdicts).unwrap();
    assert_ne!(second, first);
    // A late subscribe under the old nonce, up to 10 000 ms after the new
    // hello: the latest nonce again, and no failed attempt.
    let late = check(&mut state, &signed(&first, HOST), &hosts(), 61_000);
    assert_eq!(expired_hello(&late), Some(second));
    let edge = check(&mut state, &signed(&first, HOST), &hosts(), 70_001);
    assert_eq!(expired_hello(&edge), Some(second));
    let forged = signed(&[9; 32], HOST);
    assert!(is_bad_auth(
        &check(&mut state, &forged, &hosts(), 70_001),
        channel(DAY)
    ));
    assert!(is_bad_auth(
        &check(&mut state, &forged, &hosts(), 70_001),
        channel(DAY)
    ));
    // Past 10 000 ms the old nonce is a forgery, and this third one closes.
    let verdicts = check(&mut state, &signed(&first, HOST), &hosts(), 70_002);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadAuth { .. }, Verdict::Close]
    ));

    // A repeat hello at 9 000 ms does not restart the 10 000 ms, and the
    // latest nonce opens the channel within its own lifetime.
    let (mut state, first) = accepted();
    let second =
        expired_hello(&check(&mut state, &signed(&first, HOST), &hosts(), 60_001)).unwrap();
    let repeat = check(&mut state, &signed(&first, HOST), &hosts(), 69_001);
    assert_eq!(expired_hello(&repeat), Some(second));
    let after = check(&mut state, &signed(&first, HOST), &hosts(), 70_002);
    assert!(is_bad_auth(&after, channel(DAY)));
    assert!(is_accept(
        &check(&mut state, &signed(&second, HOST), &hosts(), 120_001),
        channel(DAY)
    ));

    // A nonce older than the previous one is a forgery.
    let (mut state, oldest) = accepted();
    let second =
        expired_hello(&check(&mut state, &signed(&oldest, HOST), &hosts(), 60_001)).unwrap();
    assert!(
        expired_hello(&check(
            &mut state,
            &signed(&second, HOST),
            &hosts(),
            120_002
        ))
        .is_some()
    );
    assert!(is_bad_auth(
        &check(&mut state, &signed(&oldest, HOST), &hosts(), 120_003),
        channel(DAY)
    ));
}

#[test]
fn s031_t05_r05_verdicts() {
    // Each vector of `031.json`, signed again under the state's nonce, on a
    // connection of its own; every verdict names the vector's `channel_id`.
    let cases: [(&str, u32, u32, Option<&str>); 11] = [
        ("auth_reference", DAY, DAY, None),
        ("auth_url_with_port", DAY, DAY, None),
        ("auth_onion_ws", DAY, DAY, None),
        ("auth_ttl_60", 60, 60, None),
        ("auth_ttl_2592000", 2_592_000, 2_592_000, None),
        ("auth_wrong_host", DAY, DAY, Some(HOST)),
        ("auth_wrong_nonce", DAY, DAY, None),
        ("auth_flipped_sig", DAY, DAY, None),
        ("auth_other_ttl", 60, 61, None),
        ("auth_ttl_59", 60, 59, None),
        ("auth_ttl_2592001", 2_592_000, 2_592_001, None),
    ];
    for (name, signing_ttl, ttl_seconds, signed_host) in cases {
        let url = String::from_utf8(hex(&vector_field(name, "server_url"))).unwrap();
        let configured = vec![relay::url_host(&url).unwrap()];
        let expected: [u8; 16] = hex(&vector_field(name, "channel_id")).try_into().unwrap();
        let (mut state, hello) = AuthState::new(0).unwrap();
        let nonce = if name == "auth_wrong_nonce" {
            [7; 32]
        } else {
            nonce_of(&hello)
        };
        let host = signed_host.unwrap_or(&configured[0]);
        let mut subscribe = sent(&nonce, signing_ttl, ttl_seconds, host);
        if name == "auth_flipped_sig" {
            subscribe.sig[0] ^= 0x01;
        }
        let verdicts = check(&mut state, &subscribe, &configured, 1);
        let right = match name {
            "auth_ttl_59" | "auth_ttl_2592001" => {
                matches!(verdicts.as_slice(), [Verdict::BadTtl { channel_id }] if *channel_id == expected)
            }
            "auth_wrong_host" | "auth_wrong_nonce" | "auth_flipped_sig" | "auth_other_ttl" => {
                is_bad_auth(&verdicts, expected)
            }
            _ => is_accept(&verdicts, expected),
        };
        assert!(right, "{name}");
    }

    // The age of the nonce comes first: an expired nonce with a bad signature
    // is `nonce_expired`, not a failed attempt.
    let (mut state, nonce) = accepted();
    let mut flipped = signed(&nonce, HOST);
    flipped.sig[0] ^= 0x01;
    assert!(expired_hello(&check(&mut state, &flipped, &hosts(), 60_001)).is_some());
}

#[test]
fn s031_t06_r06_three_failures_close() {
    let forged = signed(&[9; 32], HOST);
    let (mut state, nonce) = accepted();
    assert!(is_bad_auth(
        &check(&mut state, &forged, &hosts(), 2),
        channel(DAY)
    ));
    assert!(is_bad_auth(
        &check(&mut state, &forged, &hosts(), 3),
        channel(DAY)
    ));
    // A `nonce_expired` is no failed attempt.
    let expired = check(&mut state, &signed(&nonce, HOST), &hosts(), 60_001);
    assert!(expired_hello(&expired).is_some());
    let verdicts = check(&mut state, &forged, &hosts(), 60_002);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadAuth { .. }, Verdict::Close]
    ));

    let (mut state, hello) = AuthState::new(0).unwrap();
    let bad_ttl = sent(&nonce_of(&hello), 60, 59, HOST);
    assert!(matches!(
        check(&mut state, &bad_ttl, &hosts(), 1).as_slice(),
        [Verdict::BadTtl { .. }]
    ));
    assert!(is_bad_auth(
        &check(&mut state, &forged, &hosts(), 2),
        channel(DAY)
    ));
    let verdicts = check(&mut state, &bad_ttl, &hosts(), 3);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadTtl { .. }, Verdict::Close]
    ));
}

#[test]
fn s031_t07_r07_first_subscribe_deadline() {
    let (mut state, hello) = AuthState::new(1_000).unwrap();
    assert!(!state.deadline_passed(61_000));
    assert!(state.deadline_passed(61_001));
    // Past the deadline even a valid subscribe gets no answer but the close.
    let verdicts = check(
        &mut state,
        &signed(&nonce_of(&hello), HOST),
        &hosts(),
        61_001,
    );
    assert!(matches!(verdicts.as_slice(), [Verdict::Close]));

    let (mut state, hello) = AuthState::new(0).unwrap();
    let verdicts = check(
        &mut state,
        &signed(&nonce_of(&hello), HOST),
        &hosts(),
        30_000,
    );
    assert!(is_accept(&verdicts, channel(DAY)));
    assert!(!state.deadline_passed(30_000 + 600_000));
}

#[test]
fn s031_t08_r08_hosts_from_config() {
    let configured: Vec<String> = ["wss://chat.example.org", &format!("ws://{ONION}")]
        .iter()
        .map(|url| relay::url_host(url).unwrap())
        .collect();
    for host in [HOST, ONION] {
        let (mut state, hello) = AuthState::new(0).unwrap();
        let verdicts = check(&mut state, &signed(&nonce_of(&hello), host), &configured, 1);
        assert!(is_accept(&verdicts, channel(DAY)), "{host}");
    }
    // The port is not part of the host a configured URL gives.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let with_port = signed(&nonce_of(&hello), "chat.example.org:9001");
    assert!(is_bad_auth(
        &check(&mut state, &with_port, &configured, 1),
        channel(DAY)
    ));
}

#[test]
fn s031_t09_r09_nothing_kept() {
    // The subscription half of T09 belongs to spec 030, whose connection
    // keeps it.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let nonce = nonce_of(&hello);
    let subscribe = signed(&nonce, HOST);
    assert!(is_accept(
        &check(&mut state, &subscribe, &hosts(), 1),
        channel(DAY)
    ));
    let shown = format!("{state:?}");
    assert!(
        !shown.contains("nonce") && !shown.contains("previous"),
        "{shown}"
    );
    for bytes in [&subscribe.pk_ch[..], &subscribe.sig[..], &nonce[..]] {
        let as_hex: String = bytes[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let as_decimal = format!("{:?}", &bytes[..4]);
        assert!(!shown.contains(&as_hex), "{shown}");
        assert!(!shown.contains(as_decimal.trim_end_matches(']')), "{shown}");
    }
}
