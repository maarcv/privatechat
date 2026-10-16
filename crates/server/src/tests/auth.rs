//! Spec 031-auth-channel-signature, the server half: `AuthState` over a
//! monotonic `now`, with no socket. The client's signature comes from
//! `testing::subscribe_credential`, which signs what the session signs.

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use crate::auth::{AuthState, Verdict};

const K_CH: [u8; 32] = [0x40; 32];
const DAY: u32 = 86_400;
const HOST: &str = "chat.example.org";
const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

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

/// A `subscribe` of the test channel at `ttl_seconds`, signed under `nonce`
/// for `host`, as the server sees it.
struct Subscribe {
    pk_ch: [u8; 32],
    ttl_seconds: u32,
    sig: [u8; 64],
}

fn signed(nonce: &[u8; 32], ttl_seconds: u32, host: &str) -> Subscribe {
    // A TTL out of range is signed under one in range: the server refuses
    // it before it looks at the signature.
    let signing_ttl = ttl_seconds.clamp(60, 2_592_000);
    let (pk_ch, sig) = subscribe_credential(K_CH, signing_ttl, nonce, host).unwrap();
    Subscribe {
        pk_ch,
        ttl_seconds,
        sig,
    }
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
    let pk_ch = signed(&[0; 32], ttl_seconds, HOST).pk_ch;
    relay::channel_id(&pk_ch, ttl_seconds).unwrap()
}

fn is_accept(verdicts: &[Verdict], ttl_seconds: u32) -> bool {
    matches!(verdicts, [Verdict::Accept { channel_id }] if *channel_id == channel(ttl_seconds))
}

fn is_bad_auth(verdicts: &[Verdict]) -> bool {
    matches!(verdicts, [Verdict::BadAuth { channel_id }] if *channel_id == channel(DAY))
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

#[test]
fn s031_t01_r01_nonce_lifetime() {
    let (_, other) = AuthState::new(0).unwrap();
    let (mut state, hello) = AuthState::new(0).unwrap();
    let first = nonce_of(&hello);
    assert_eq!(versions_of(&hello), [1]);
    assert_ne!(first, [0; 32]);
    assert_ne!(first, nonce_of(&other));
    assert!(is_accept(
        &check(&mut state, &signed(&first, DAY, HOST), &hosts(), 59_999),
        DAY
    ));

    // 60 001 ms after its hello the nonce has expired: a new one comes.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let first = nonce_of(&hello);
    let verdicts = check(&mut state, &signed(&first, DAY, HOST), &hosts(), 60_001);
    let second = expired_hello(&verdicts).unwrap();
    assert_ne!(second, first);
    // A late subscribe under the old nonce: the latest nonce again, and no
    // failed attempt (two more failures do not close).
    let late = check(&mut state, &signed(&first, DAY, HOST), &hosts(), 61_000);
    assert_eq!(expired_hello(&late), Some(second));
    let forged = signed(&[9; 32], DAY, HOST);
    assert!(is_bad_auth(&check(&mut state, &forged, &hosts(), 61_001)));
    assert!(is_bad_auth(&check(&mut state, &forged, &hosts(), 61_002)));
    // Past 10 000 ms of the latest nonce's first hello, the old nonce is
    // a forgery, and the third one closes.
    let verdicts = check(&mut state, &signed(&first, DAY, HOST), &hosts(), 70_002);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadAuth { .. }, Verdict::Close]
    ));
    // The latest nonce still opens the channel within its lifetime.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let verdicts = check(
        &mut state,
        &signed(&nonce_of(&hello), DAY, HOST),
        &hosts(),
        60_001,
    );
    let second = expired_hello(&verdicts).unwrap();
    // A repeat hello at 9 000 ms does not restart the 10 000 ms.
    let repeat = check(
        &mut state,
        &signed(&nonce_of(&hello), DAY, HOST),
        &hosts(),
        69_000,
    );
    assert_eq!(expired_hello(&repeat), Some(second));
    let after = check(
        &mut state,
        &signed(&nonce_of(&hello), DAY, HOST),
        &hosts(),
        70_002,
    );
    assert!(is_bad_auth(&after));
    assert!(is_accept(
        &check(&mut state, &signed(&second, DAY, HOST), &hosts(), 120_001),
        DAY
    ));

    // A nonce older than the previous one is a forgery.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let oldest = nonce_of(&hello);
    let second = expired_hello(&check(
        &mut state,
        &signed(&oldest, DAY, HOST),
        &hosts(),
        60_001,
    ))
    .unwrap();
    let third = check(&mut state, &signed(&second, DAY, HOST), &hosts(), 120_002);
    assert!(expired_hello(&third).is_some());
    assert!(is_bad_auth(&check(
        &mut state,
        &signed(&oldest, DAY, HOST),
        &hosts(),
        120_003
    )));
}

#[test]
fn s031_t05_r05_verdicts() {
    let (mut state, hello) = AuthState::new(0).unwrap();
    let nonce = nonce_of(&hello);
    assert!(is_accept(
        &check(&mut state, &signed(&nonce, DAY, HOST), &hosts(), 1),
        DAY
    ));
    // Each refusal names the channel the client sent.
    for ttl_seconds in [59, 2_592_001] {
        let verdicts = check(&mut state, &signed(&nonce, ttl_seconds, HOST), &hosts(), 2);
        assert!(
            matches!(verdicts.as_slice(), [Verdict::BadTtl { channel_id }] if *channel_id == channel(ttl_seconds)),
            "{ttl_seconds}"
        );
    }
    let (mut state, hello) = AuthState::new(0).unwrap();
    let nonce = nonce_of(&hello);
    assert!(is_bad_auth(&check(
        &mut state,
        &signed(&nonce, DAY, "other.example.org"),
        &hosts(),
        1
    )));
    let mut flipped = signed(&nonce, DAY, HOST);
    flipped.sig[0] ^= 0x01;
    assert!(is_bad_auth(&check(&mut state, &flipped, &hosts(), 2)));

    // The age of the nonce comes first: an expired nonce with a bad signature
    // is `nonce_expired`, not a failed attempt.
    let (mut state, _) = AuthState::new(0).unwrap();
    assert!(expired_hello(&check(&mut state, &flipped, &hosts(), 60_001)).is_some());
}

#[test]
fn s031_t06_r06_three_failures_close() {
    let forged = signed(&[9; 32], DAY, HOST);
    let (mut state, hello) = AuthState::new(0).unwrap();
    assert!(is_bad_auth(&check(&mut state, &forged, &hosts(), 1)));
    assert!(is_bad_auth(&check(&mut state, &forged, &hosts(), 2)));
    // A `nonce_expired` is no failed attempt.
    let expired = check(
        &mut state,
        &signed(&nonce_of(&hello), DAY, HOST),
        &hosts(),
        60_001,
    );
    assert!(expired_hello(&expired).is_some());
    let verdicts = check(&mut state, &forged, &hosts(), 60_002);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadAuth { .. }, Verdict::Close]
    ));

    let (mut state, hello) = AuthState::new(0).unwrap();
    let nonce = nonce_of(&hello);
    let bad_ttl = signed(&nonce, 59, HOST);
    assert!(matches!(
        check(&mut state, &bad_ttl, &hosts(), 1).as_slice(),
        [Verdict::BadTtl { .. }]
    ));
    assert!(is_bad_auth(&check(&mut state, &forged, &hosts(), 2)));
    let verdicts = check(&mut state, &bad_ttl, &hosts(), 3);
    assert!(matches!(
        verdicts.as_slice(),
        [Verdict::BadTtl { .. }, Verdict::Close]
    ));
}

#[test]
fn s031_t07_r07_first_subscribe_deadline() {
    let (state, _) = AuthState::new(1_000).unwrap();
    assert!(!state.deadline_passed(61_000));
    assert!(state.deadline_passed(61_001));

    let (mut state, hello) = AuthState::new(0).unwrap();
    assert!(is_accept(
        &check(
            &mut state,
            &signed(&nonce_of(&hello), DAY, HOST),
            &hosts(),
            30_000
        ),
        DAY
    ));
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
        let verdicts = check(
            &mut state,
            &signed(&nonce_of(&hello), DAY, host),
            &configured,
            1,
        );
        assert!(is_accept(&verdicts, DAY), "{host}");
    }
    // The port is not part of the host a configured URL gives.
    let (mut state, hello) = AuthState::new(0).unwrap();
    let with_port = signed(&nonce_of(&hello), DAY, "chat.example.org:9001");
    assert!(is_bad_auth(&check(&mut state, &with_port, &configured, 1)));
}

#[test]
fn s031_t09_r09_nothing_kept() {
    let (mut state, hello) = AuthState::new(0).unwrap();
    let subscribe = signed(&nonce_of(&hello), DAY, HOST);
    assert!(is_accept(&check(&mut state, &subscribe, &hosts(), 1), DAY));
    let shown = format!("{state:?}");
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    for secretless in [
        hex(&subscribe.pk_ch),
        hex(&subscribe.sig),
        hex(&nonce_of(&hello)),
    ] {
        assert!(!shown.contains(&secretless[..8]), "{shown}");
    }
}
