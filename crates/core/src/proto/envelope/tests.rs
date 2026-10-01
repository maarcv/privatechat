//! Tests of spec 013 over the inputs of `text_k1`: the envelope, the order
//! of `verify`, `open`, the mutation table and its property, the blob-level
//! halves of T12–T14, and the dispatch of `013.json`.

use proptest::prelude::{ProptestConfig, any, proptest};

use super::text_k1::{
    BODY, COUNTER, CREATED_AT, K_CH, NONCE, NOW, RECEIVED_AT, SENDER_SEED, SENT_AT, SERVER_URL,
    SUGGESTED_NAME, TTL_SECONDS,
};
use super::{
    BLOB_OVERHEAD, ChannelCtx, Content, EXPIRY_MARGIN_MS, HEADER_LEN, KEY_RETIRED_COUNTER,
    MSG_SIGNATURE_TAG, Opened, PROTO_V1, Sealed, SenderKey, seal, seal_padded, ttl_ms, verify, xor,
};
use crate::Error::{self, BadLength, BadSignature, Expired, UnsupportedVersion, WrongChannel};
use crate::crypto::{self, Nonce, Secret, TAG_LEN};
use crate::proto::config::{ChannelId, Config};
use crate::proto::header::{Header, header_keystream};
use crate::proto::keys::{ChannelKeys, message_key};
use crate::proto::payload::{
    MAX_BLOCKS, MAX_DISPLAY_NAME, MAX_PAYLOAD, PAD_BLOCK, Payload, PayloadKind,
};
use crate::vectors::{self, Checker, Vector};

fn config(k_ch: [u8; 32]) -> Config {
    Config::from_parts(
        Secret::from_bytes(k_ch),
        SERVER_URL,
        TTL_SECONDS,
        SUGGESTED_NAME,
        CREATED_AT,
    )
    .unwrap()
}

fn ctx() -> ChannelCtx {
    ChannelCtx::from_config(&config(K_CH)).unwrap()
}

fn sender(seed: [u8; 32]) -> SenderKey {
    SenderKey::from_seed(&Secret::from_bytes(seed)).unwrap()
}

/// The blob of `text_k1`.
fn sealed() -> Sealed {
    let payload = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: SENT_AT,
        body: BODY.to_vec(),
    };
    seal(
        &ctx(),
        &sender(SENDER_SEED),
        COUNTER,
        &Nonce(NONCE),
        &payload,
    )
    .unwrap()
}

/// `verify` at the times of `text_k1`, with the verdict alone.
fn verdict(blob: &[u8]) -> Result<(), Error> {
    verify(blob, &ctx(), RECEIVED_AT, NOW).map(|_| ())
}

fn flipped(mut blob: Vec<u8>, offset: usize) -> Vec<u8> {
    blob[offset] ^= 0x01;
    blob
}

/// `blob` with its last 64 bytes replaced by `signature` masked as it
/// travels (ADR 0032).
fn with_signature(mut blob: Vec<u8>, signature: [u8; 64]) -> Vec<u8> {
    let stream = header_keystream(&ctx().keys, &Nonce(NONCE)).unwrap();
    let at = blob.len() - 64;
    blob[at..].copy_from_slice(&xor(signature, stream[40..].try_into().unwrap()));
    blob
}

/// Spec 013, R1: each field sits at the offset of the table.
#[test]
fn s013_t01_r01_envelope_offsets() {
    let blob = sealed().blob;
    let n = blob.len() - HEADER_LEN - 64;
    assert_eq!(blob.len(), BLOB_OVERHEAD + PAD_BLOCK);
    assert_eq!(n, TAG_LEN + PAD_BLOCK);
    assert_eq!(blob[0], PROTO_V1);
    assert_eq!(blob[1..17], config(K_CH).channel_id());
    let stream = header_keystream(&ctx().keys, &Nonce(NONCE)).unwrap();
    let header = Header {
        sender_pk: *sender(SENDER_SEED).public(),
        counter: COUNTER,
    };
    let enc_hdr = xor(header.to_bytes(), stream[..40].try_into().unwrap());
    assert_eq!(blob[17..57], enc_hdr);
    assert_eq!(blob[57..81], NONCE);
    let ctx = ctx();
    let verified = verify(&blob, &ctx, RECEIVED_AT, NOW).unwrap();
    assert_eq!(verified.envelope.ciphertext, &blob[81..81 + n]);
    assert_eq!(verified.envelope.signature, &blob[81 + n..]);
}

/// Spec 013, R2: every length off the class 161 + 1 024·k, k in 1..=63.
#[test]
fn s013_t02_r02_rejects_bad_length() {
    // 161 + 1 024·64 is the first aligned length above the class; the spec's
    // 1 185 + 1 024·64 is k = 65.
    for len in [
        0,
        160,
        161,
        1_184,
        1_186,
        64_674,
        161 + 1_024 * 64,
        1_185 + 1_024 * 64,
    ] {
        let mut blob = sealed().blob;
        blob.resize(len, 0);
        assert_eq!(verdict(&blob), Err(BadLength), "{len}");
    }
}

/// Spec 013, R2: a version other than 0x01.
#[test]
fn s013_t03_r02_rejects_other_versions() {
    for version in [0x00, 0x02] {
        let mut blob = sealed().blob;
        blob[0] = version;
        assert_eq!(verdict(&blob), Err(UnsupportedVersion), "{version}");
    }
}

/// Spec 013, R2: a `channel_id` one byte apart, and a context of another
/// channel.
#[test]
fn s013_t04_r02_rejects_another_channel() {
    assert_eq!(verdict(&flipped(sealed().blob, 16)), Err(WrongChannel));
    let other = ChannelCtx::from_config(&config([0x99; 32])).unwrap();
    let blob = sealed().blob;
    assert!(matches!(
        verify(&blob, &other, RECEIVED_AT, NOW),
        Err(WrongChannel)
    ));
}

/// Spec 013, R3: the AEAD opens under `blob[0..81]` and under nothing else.
#[test]
fn s013_t05_r03_aad_is_the_first_81_bytes() {
    let blob = sealed().blob;
    let mk = message_key(&ctx().keys, sender(SENDER_SEED).public(), COUNTER).unwrap();
    let ciphertext = &blob[HEADER_LEN..blob.len() - 64];
    let open = |aad: &[u8]| crypto::aead_decrypt(&mk, &Nonce(NONCE), aad, ciphertext).is_ok();
    assert!(open(&blob[..HEADER_LEN]));
    for aad in [
        &blob[..HEADER_LEN - 1],
        &blob[1..HEADER_LEN],
        &blob[..HEADER_LEN + 1],
        &flipped(blob[..HEADER_LEN].to_vec(), 40),
        &[],
    ] {
        assert!(!open(aad), "{}", aad.len());
    }
}

/// Spec 013, R4: the signature is Ed25519 over the tag and `blob[0..81 + n]`
/// and travels masked; unmasked in place, it is refused. The dispatch
/// checks the bytes of `text_k1`.
#[test]
fn s013_t06_r04_signature_known_answer() {
    let Sealed { blob, signature } = sealed();
    let signed = [MSG_SIGNATURE_TAG.as_slice(), &blob[..blob.len() - 64]].concat();
    let public = *sender(SENDER_SEED).public();
    assert!(crypto::verify_detached(&public, &signed, &crypto::Signature(signature)).is_ok());
    assert_ne!(blob[blob.len() - 64..], signature);
    let mut unmasked = blob;
    let at = unmasked.len() - 64;
    unmasked[at..].copy_from_slice(&signature);
    assert_eq!(verdict(&unmasked), Err(BadSignature));
}

/// Spec 013, R4: a valid header with the signature of another key over the
/// same bytes, or of no key, is refused by `verify`.
#[test]
fn s013_t07_r04_signature_before_state_and_aead() {
    let Sealed { blob, signature } = sealed();
    let signed = [MSG_SIGNATURE_TAG.as_slice(), &blob[..blob.len() - 64]].concat();
    let other = SenderKey::from_seed(&Secret::from_bytes([0x98; 32])).unwrap();
    let forged = crypto::sign_detached(&other.sk, &signed).unwrap();
    assert_eq!(verdict(&with_signature(blob.clone(), signature)), Ok(()));
    assert_eq!(
        verdict(&with_signature(blob.clone(), forged.0)),
        Err(BadSignature)
    );
    assert_eq!(verdict(&with_signature(blob, [0; 64])), Err(BadSignature));
}

/// Spec 013, R4: a signature over the ciphertext alone is refused, before
/// and after a counter bit is flipped (vector `signed_ciphertext_only`).
#[test]
fn s013_t08_r04_signature_covers_the_header() {
    let blob = sealed().blob;
    let ciphertext_only = [
        MSG_SIGNATURE_TAG.as_slice(),
        &blob[HEADER_LEN..blob.len() - 64],
    ];
    let key = sender(SENDER_SEED);
    let signature = crypto::sign_detached(&key.sk, &ciphertext_only.concat()).unwrap();
    let blob = with_signature(blob, signature.0);
    assert_eq!(verdict(&blob), Err(BadSignature));
    assert_eq!(verdict(&flipped(blob, 56)), Err(BadSignature));
}

/// Spec 013, R5: the nonce at offset 57 is the one passed and the one that
/// opens the header, whose key is the sender's.
#[test]
fn s013_t09_r05_seal_uses_the_given_nonce() {
    let key = sender(SENDER_SEED);
    let payload = Payload {
        kind: PayloadKind::KeyRetired,
        display_name: None,
        sent_at: SENT_AT,
        body: Vec::new(),
    };
    for nonce in [NONCE, [0x5a; 24]] {
        let blob = seal(&ctx(), &key, COUNTER, &Nonce(nonce), &payload)
            .unwrap()
            .blob;
        assert_eq!(blob[57..81], nonce);
        let stream = header_keystream(&ctx().keys, &Nonce(nonce)).unwrap();
        let header = Header::from_bytes(&xor(
            blob[17..57].try_into().unwrap(),
            stream[..40].try_into().unwrap(),
        ));
        assert_eq!(header.sender_pk.0, key.public().0);
        let ctx = ctx();
        let verified = verify(&blob, &ctx, RECEIVED_AT, NOW).unwrap();
        assert_eq!(verified.sender_pk().0, key.public().0);
        assert_eq!(verified.counter(), COUNTER);
    }
}

/// The blob of `text_k1` with the defects of `steps`, indices into `STEPS`,
/// and its `received_at`.
fn broken(steps: &[usize]) -> (Vec<u8>, u64) {
    let mut blob = sealed().blob;
    let mut received_at = RECEIVED_AT;
    for step in steps {
        match step {
            0 => blob.push(0),
            1 => blob[0] = 0x02,
            2 => blob[1] ^= 0x01,
            3 => received_at = 0,
            _ => blob[HEADER_LEN + 100] ^= 0x01,
        }
    }
    (blob, received_at)
}

/// The steps of R11 in order, and their errors.
const STEPS: [Error; 5] = [
    BadLength,
    UnsupportedVersion,
    WrongChannel,
    Expired,
    BadSignature,
];

/// Spec 013, R11: of two failing steps, the first wins, for every pair;
/// and the step-2 boundary of the worked example.
#[test]
fn s013_t15_r11_check_order() {
    let ctx = ctx();
    for (first, error) in STEPS.iter().enumerate() {
        for second in first..STEPS.len() {
            // A defect applied twice would undo itself.
            let steps = if first == second {
                &[first][..]
            } else {
                &[first, second]
            };
            let (blob, received_at) = broken(steps);
            let verdict = verify(&blob, &ctx, received_at, NOW).map(|_| ());
            assert_eq!(verdict, Err(*error), "steps {first} and {second}");
        }
    }
    let blob = sealed().blob;
    let now = 1_004_000_000;
    assert!(matches!(
        verify(&blob, &ctx, 1_000_039_999, now),
        Err(Expired)
    ));
    assert!(verify(&blob, &ctx, 1_000_040_000, now).is_ok());
    assert!(
        verify(&blob, &ctx, now, 1_000_040_000).is_ok(),
        "a received_at after now"
    );
}

/// Spec 013, R15: the constants are the literals of `docs/spec.md` §4.
#[test]
fn s013_t19_r15_literals() {
    assert_eq!(PROTO_V1, 0x01);
    assert_eq!(HEADER_LEN, 81);
    assert_eq!((PAD_BLOCK, MAX_BLOCKS, BLOB_OVERHEAD), (1_024, 63, 161));
    assert_eq!(BLOB_OVERHEAD, HEADER_LEN + TAG_LEN + 64);
    assert_eq!((MAX_PAYLOAD, MAX_DISPLAY_NAME), (64_511, 64));
    assert_eq!(MAX_PAYLOAD, PAD_BLOCK * MAX_BLOCKS - 1);
    assert_eq!(MSG_SIGNATURE_TAG, b"privatechat/msg/v1");
    assert_eq!(MSG_SIGNATURE_TAG.len(), 18);
    assert_eq!(EXPIRY_MARGIN_MS, 360_000);
    assert_eq!(KEY_RETIRED_COUNTER, u64::MAX);
    assert_eq!(ttl_ms(3_600), 3_600_000);
    assert_eq!(ttl_ms(u32::MAX), u64::from(u32::MAX) * 1_000);
    let spec = include_str!("../../../../../docs/spec.md");
    for literal in [
        "| 0 | 1 | `proto_version` = 0x01 |",
        "| 1 | 16 | `channel_id` |",
        "| 17 | 40 | `enc_hdr`",
        "| 57 | 24 | `nonce` |",
        "| 81 | n | `ciphertext`, n = 16 + 1 024·k, 1 ≤ k ≤ 63 |",
        "| 81+n | 64 | `signature`",
        "minimum 1 185 B, maximum 64 673 B",
        "| `privatechat/msg/v1` | message envelope signature |",
        "`min(received_at, now) + ttl_ms + 360 000 < now`",
        "maximum size before padding 64 511 B",
        "`counter = 2^64 − 1`",
    ] {
        assert!(spec.contains(literal), "{literal}");
    }
}

/// Spec 013, R1, R2, R4, R17: one flipped byte per region of `text_k1`, and
/// the length, each refused by `verify` with the region's error, so that no
/// `Verified` exists to open.
#[test]
fn s013_t22_r17_mutation_table() {
    let blob = sealed().blob;
    let last = blob.len() - 1;
    for (region, offset, error) in [
        ("proto_version", 0, UnsupportedVersion),
        ("channel_id", 9, WrongChannel),
        ("enc_hdr", 30, BadSignature),
        ("nonce", 70, BadSignature),
        ("ciphertext", 600, BadSignature),
        ("signature", last - 10, BadSignature),
    ] {
        assert_eq!(
            verdict(&flipped(blob.clone(), offset)),
            Err(error),
            "{region}"
        );
    }
    assert_eq!(verdict(&blob[..last]), Err(BadLength));
    assert_eq!(verdict(&[blob.as_slice(), &[0]].concat()), Err(BadLength));
}

/// Spec 013, R19: the context of a config is its id, its keys and its TTL.
#[test]
fn s013_t24_r19_context_from_config() {
    let config = config(K_CH);
    let ctx = ChannelCtx::from_config(&config).unwrap();
    assert_eq!(ctx.id.0, config.channel_id());
    let keys = ChannelKeys::derive(&Secret::from_bytes(K_CH)).unwrap();
    assert!(ctx.keys.msg == keys.msg && ctx.keys.hdr == keys.hdr);
    assert_eq!(ctx.ttl_seconds, TTL_SECONDS);
}

/// Spec 013, R20: `Sealed` and `Verified` give the signature unmasked, and
/// masked it is the blob's last 64 bytes.
#[test]
fn s013_t25_r20_signature_is_unmasked() {
    let Sealed { blob, signature } = sealed();
    let ctx = ctx();
    let verified = verify(&blob, &ctx, RECEIVED_AT, NOW).unwrap();
    assert_eq!(verified.signature(), &signature);
    let stream = header_keystream(&ctx.keys, &Nonce(NONCE)).unwrap();
    assert_eq!(
        blob[blob.len() - 64..],
        xor(signature, stream[40..].try_into().unwrap())
    );
}

/// Spec 013, R16 (Interface): `seal_padded` takes 1 024·k bytes with k in
/// 1..=63 and nothing else.
#[test]
fn s013_t20_r16_seal_padded_checks_its_length() {
    let key = sender(SENDER_SEED);
    for len in [0, 1_023, 1_025, PAD_BLOCK * (MAX_BLOCKS + 1)] {
        let sealed = seal_padded(&ctx(), &key, COUNTER, &Nonce(NONCE), &vec![0; len]);
        assert!(matches!(sealed, Err(Error::BadPayload)), "{len}");
    }
    for len in [PAD_BLOCK, PAD_BLOCK * MAX_BLOCKS] {
        assert!(seal_padded(&ctx(), &key, COUNTER, &Nonce(NONCE), &vec![0; len]).is_ok());
    }
}

/// `payload` encoded and padded with no validation, as a non-conforming
/// sender could.
fn padded(payload: &Payload) -> Vec<u8> {
    let mut padded = payload.encode().unwrap();
    crypto::pad(&mut padded, PAD_BLOCK).unwrap();
    padded
}

/// `padded` sealed by the sender of `text_k1`, then verified and opened at
/// the times given.
fn open_padded(padded: &[u8], received_at: u64, now: u64) -> Result<Opened, Error> {
    let ctx = ctx();
    let key = sender(SENDER_SEED);
    let blob = seal_padded(&ctx, &key, COUNTER, &Nonce(NONCE), padded)?.blob;
    verify(&blob, &ctx, received_at, now)?.open()
}

fn text(sent_at: u64, body: &[u8]) -> Payload {
    Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at,
        body: body.to_vec(),
    }
}

/// `payload` sealed with `seal`, verified and opened at `received_at = now`.
fn round_trip(payload: &Payload, now: u64) -> Result<Opened, Error> {
    let ctx = ctx();
    let blob = seal(&ctx, &sender(SENDER_SEED), COUNTER, &Nonce(NONCE), payload)?.blob;
    verify(&blob, &ctx, now, now)?.open()
}

/// Spec 013, R8: a `sent_at` off the minute fails `seal` and, sealed anyway,
/// opens as `Unreadable` with its `sent_at` read.
#[test]
fn s013_t12_r08_sent_at_off_the_minute_on_the_wire() {
    let payload = text(60_001, BODY);
    assert!(matches!(
        round_trip(&payload, 61_000),
        Err(Error::BadPayload)
    ));
    let opened = open_padded(&padded(&payload), 61_000, 61_000).unwrap();
    assert_eq!(
        (opened.sent_at, opened.content),
        (Some(60_001), Content::Unreadable)
    );
}

/// Spec 013, R9: the four bad names, authentic, open as a `Message` with no
/// name.
#[test]
fn s013_t13_r09_bad_display_name_opens_without_it() {
    let names: [&[u8]; 4] = [&[b'a'; MAX_DISPLAY_NAME + 1], b"a\tb", b"a\xff", b"Ana"];
    for (index, name) in names.into_iter().enumerate() {
        let (kind, body) = if index == 3 { (1, &b""[..]) } else { (0, BODY) };
        let record = [
            &[0, 0, 0, 0, 1, kind, 1, 0, 0, 0][..],
            &[u8::try_from(name.len()).unwrap()],
            name,
            &[2, 0, 0, 0, 8],
            &SENT_AT.to_be_bytes(),
            &[3, 0, 0, 0, u8::try_from(body.len()).unwrap()],
            body,
        ]
        .concat();
        let mut padded = record;
        crypto::pad(&mut padded, PAD_BLOCK).unwrap();
        let expected = Payload {
            kind: if kind == 0 {
                PayloadKind::Text
            } else {
                PayloadKind::KeyRetired
            },
            ..text(SENT_AT, body)
        };
        let opened = open_padded(&padded, RECEIVED_AT, NOW).unwrap();
        assert_eq!(opened.content, Content::Message(expected), "{index}");
    }
}

/// Spec 013, R10: each padded size gives a blob of 161 + 1 024·k bytes, and
/// 64 512 encoded bytes do not seal.
#[test]
fn s013_t14_r10_blob_sizes() {
    for (encoded, blocks) in [(24, 1), (1_023, 1), (1_024, 2), (MAX_PAYLOAD, MAX_BLOCKS)] {
        let payload = text(SENT_AT, &vec![b'a'; encoded - 24]);
        let blob = seal(
            &ctx(),
            &sender(SENDER_SEED),
            COUNTER,
            &Nonce(NONCE),
            &payload,
        )
        .unwrap()
        .blob;
        assert_eq!(blob.len(), BLOB_OVERHEAD + PAD_BLOCK * blocks, "{encoded}");
    }
    let too_long = text(SENT_AT, &vec![b'a'; MAX_PAYLOAD + 1 - 24]);
    assert!(matches!(
        round_trip(&too_long, SENT_AT),
        Err(Error::BadPayload)
    ));
}

/// Spec 013, R12: the outcomes of `open`, the stale check before anything
/// after key 2, and `sent_at` exactly when key 2 was read.
#[test]
fn s013_t16_r12_open_outcomes() {
    let unknown = Payload {
        kind: PayloadKind::Unknown(9),
        ..text(SENT_AT, BODY)
    };
    let record = padded(&text(SENT_AT, BODY));
    let mut no_marker = text(SENT_AT, BODY).encode().unwrap();
    no_marker.resize(PAD_BLOCK, 0);
    let fields = |fields: &[&[u8]]| {
        let mut padded = fields.concat();
        crypto::pad(&mut padded, PAD_BLOCK).unwrap();
        padded
    };
    let type_field: &[u8] = &[0, 0, 0, 0, 1, 0];
    let sent_at_field = |sent_at: u64| [&[2, 0, 0, 0, 8][..], &sent_at.to_be_bytes()].concat();
    let body_field: &[u8] = &[3, 0, 0, 0, 1, b'x'];
    let stale = 1_000_000_000;
    let cases: [(&str, Vec<u8>, Option<u64>, Content); 11] = [
        ("broken padding", no_marker, None, Content::Unreadable),
        (
            "broken record",
            fields(&[type_field, &sent_at_field(SENT_AT), body_field, body_field]),
            Some(SENT_AT),
            Content::Unreadable,
        ),
        (
            "unknown type",
            padded(&unknown),
            Some(SENT_AT),
            Content::Unreadable,
        ),
        (
            "no key 2",
            fields(&[type_field, body_field]),
            None,
            Content::Unreadable,
        ),
        (
            "key 2 of 7 bytes",
            fields(&[
                type_field,
                &[2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
                body_field,
            ]),
            None,
            Content::Unreadable,
        ),
        (
            "stale, unknown type",
            padded(&Payload {
                sent_at: stale,
                ..unknown
            }),
            Some(stale),
            Content::Stale,
        ),
        (
            "stale, off the minute",
            padded(&text(stale + 1, BODY)),
            Some(stale + 1),
            Content::Stale,
        ),
        (
            "stale, then a partial field",
            fields(&[type_field, &sent_at_field(stale), &[3, 0]]),
            Some(stale),
            Content::Stale,
        ),
        (
            "no key 0",
            fields(&[&sent_at_field(SENT_AT), body_field]),
            Some(SENT_AT),
            Content::Unreadable,
        ),
        (
            "stale, no key 0",
            fields(&[&sent_at_field(stale), body_field]),
            Some(stale),
            Content::Stale,
        ),
        (
            "stale, a type of 2 bytes before key 2",
            fields(&[&[0, 0, 0, 0, 2, 0, 0], &sent_at_field(stale), body_field]),
            None,
            Content::Unreadable,
        ),
    ];
    for (case, padded, sent_at, content) in cases {
        let opened = open_padded(&padded, RECEIVED_AT, NOW).unwrap();
        assert_eq!(
            (opened.sent_at, opened.content),
            (sent_at, content),
            "{case}"
        );
    }
    let opened = open_padded(&record, RECEIVED_AT, NOW).unwrap();
    assert_eq!(opened.sent_at, Some(SENT_AT));
    assert_eq!(opened.content, Content::Message(text(SENT_AT, BODY)));
    assert_eq!(
        (opened.sender_pk.0, opened.counter),
        (sender(SENDER_SEED).public().0, COUNTER)
    );
}

/// Spec 013, R12: the stale and future cases of the worked example, sealed
/// with `seal` at `received_at = now`.
#[test]
fn s013_t16_r12_stale_worked_example() {
    for (now, sent_at, is_stale) in [
        (10_000_000_000, 6_000_000_000, true),
        (10_000_000_000, 9_996_060_000, false),
        (9_999_960_000, 10_003_920_000, false),
        (9_999_960_000, 10_003_980_000, true),
    ] {
        let opened = round_trip(&text(sent_at, BODY), now).unwrap();
        let expected = if is_stale {
            Content::Stale
        } else {
            Content::Message(text(sent_at, BODY))
        };
        assert_eq!(
            (opened.sent_at, opened.content),
            (Some(sent_at), expected),
            "{sent_at}"
        );
    }
}

/// Spec 013, R12: the two bounds of the stale check exactly, with
/// `window = ttl_ms + 360 000`, and `min(received_at, now)` with either
/// time the earlier one: fresh while `sent_at + window` is not below the
/// earlier time and `now + window` is not below `sent_at`.
#[test]
fn s013_t16_r12_stale_bounds_exactly() {
    let window = ttl_ms(TTL_SECONDS) + EXPIRY_MARGIN_MS;
    let sent_at = 9_996_000_000;
    let bound = sent_at + window;
    for (received_at, now, is_stale) in [
        (bound, bound, false),
        (bound + 1, bound + 1, true),
        (bound, bound + 1_000, false),
        (bound + 1_000, bound, false),
        (bound + 1, bound + 1_000, true),
    ] {
        let payload = text(sent_at, BODY);
        let ctx = ctx();
        let blob = seal(&ctx, &sender(SENDER_SEED), COUNTER, &Nonce(NONCE), &payload)
            .unwrap()
            .blob;
        let opened = verify(&blob, &ctx, received_at, now)
            .unwrap()
            .open()
            .unwrap();
        let expected = if is_stale {
            Content::Stale
        } else {
            Content::Message(payload)
        };
        assert_eq!(opened.content, expected, "{received_at} {now}");
    }
    let sent_at = 10_003_920_000;
    let now = sent_at - window;
    for (received_at, now, is_stale) in [
        (now, now, false),
        (now - 1_000, now, false),
        (now - 1, now - 1, true),
    ] {
        let payload = text(sent_at, BODY);
        let opened = open_padded(&padded(&payload), received_at, now).unwrap();
        let expected = if is_stale {
            Content::Stale
        } else {
            Content::Message(payload)
        };
        assert_eq!(opened.content, expected, "{received_at} {now}");
    }
}

/// Spec 013, R12: a ciphertext under another `K_msg`, validly signed, passes
/// `verify` and fails the AEAD of `open`.
#[test]
fn s013_t16_r12_forged_aead_is_bad_signature() {
    let real = ctx();
    let forged = ChannelCtx {
        id: ChannelId(real.id.0),
        keys: ChannelKeys {
            msg: Secret::from_bytes([0x97; 32]),
            hdr: Secret::from_bytes(*real.keys.hdr.expose()),
        },
        ttl_seconds: TTL_SECONDS,
    };
    let blob = seal(
        &forged,
        &sender(SENDER_SEED),
        COUNTER,
        &Nonce(NONCE),
        &text(SENT_AT, BODY),
    )
    .unwrap()
    .blob;
    let verified = verify(&blob, &real, RECEIVED_AT, NOW).unwrap();
    assert!(matches!(verified.open(), Err(Error::BadSignature)));
}

/// Spec 013, R13: the extremes of every time give their exact verdict and
/// no panic: nothing wraps.
#[test]
fn s013_t17_r13_time_arithmetic_saturates() {
    let max = u64::MAX;
    let last_minute = max - max % 60_000;
    let message = |sent_at| Ok(Content::Message(text(sent_at, BODY)));
    for (sent_at, received_at, now, verdict) in [
        (0, 0, 0, message(0)),
        (0, max, max, Ok(Content::Stale)),
        (0, 0, max, Err(Error::Expired)),
        (0, max, 0, message(0)),
        (last_minute, max, max, message(last_minute)),
        (last_minute, 0, 0, Ok(Content::Stale)),
        (last_minute, max, 0, Ok(Content::Stale)),
        (max, max, max, Ok(Content::Unreadable)),
        (max, 0, 0, Ok(Content::Stale)),
        (max, 0, max, Err(Error::Expired)),
        (max, max, 0, Ok(Content::Stale)),
    ] {
        let opened = open_padded(&padded(&text(sent_at, BODY)), received_at, now);
        let content = opened.map(|opened| opened.content);
        assert_eq!(content, verdict, "{sent_at} {received_at} {now}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 013, R16: over every k, both types and names of 0..=64 bytes,
    /// `seal`, `verify` and `open` give the payload back; the same inputs
    /// give the same bytes; `seal` is `seal_padded` over the padded
    /// encoding.
    #[test]
    fn s013_t20_r16_seal_round_trip(
        is_text in any::<bool>(),
        blocks in 1..=MAX_BLOCKS,
        fill in 0..PAD_BLOCK,
        name_len in proptest::option::of(0..=MAX_DISPLAY_NAME),
        counter in any::<u64>(),
    ) {
        let payload = if is_text {
            let name = name_len.map(|len| "n".repeat(len));
            let overhead = 24 + name_len.map_or(0, |len| 5 + len);
            let target = (PAD_BLOCK * (blocks - 1) + fill).clamp(overhead, MAX_PAYLOAD);
            Payload { display_name: name, ..text(SENT_AT, &vec![b'b'; target - overhead]) }
        } else {
            Payload { kind: PayloadKind::KeyRetired, ..text(SENT_AT, b"") }
        };
        let ctx = ctx();
        let key = sender(SENDER_SEED);
        let sealed = seal(&ctx, &key, counter, &Nonce(NONCE), &payload).unwrap();
        let again = seal(&ctx, &key, counter, &Nonce(NONCE), &payload).unwrap();
        assert_eq!(&sealed.blob, &again.blob);
        let direct = seal_padded(&ctx, &key, counter, &Nonce(NONCE), &padded(&payload));
        assert_eq!(&sealed.blob, &direct.unwrap().blob);
        let opened = verify(&sealed.blob, &ctx, RECEIVED_AT, NOW).unwrap().open().unwrap();
        assert_eq!(opened.content, Content::Message(payload));
    }

    /// Spec 013, R17: for any blob, any byte and any non-zero mask, `verify`
    /// refuses with the error of the byte's region, so `open` is never
    /// reached.
    #[test]
    fn s013_t21_r17_every_flipped_byte_is_rejected_by_verify(
        body_len in 0..=MAX_PAYLOAD - 24,
        offset in any::<usize>(),
        mask in 1..=u8::MAX,
    ) {
        let blob = seal(&ctx(), &sender(SENDER_SEED), COUNTER, &Nonce(NONCE), &text(SENT_AT, &vec![b'c'; body_len]))
            .unwrap()
            .blob;
        let offset = offset % blob.len();
        let mut mutated = blob;
        mutated[offset] ^= mask;
        let expected = match offset {
            0 => UnsupportedVersion,
            1..17 => WrongChannel,
            _ => BadSignature,
        };
        assert_eq!(verdict(&mutated), Err(expected), "{offset}");
    }
}

/// Every vector's channel is `text_k1`'s (spec 013, "Vectors").
fn check_channel(vector: &Vector) {
    assert_eq!(vector.input("k_ch").array(), K_CH, "{}", vector.name());
    assert_eq!(vector.input("ttl_seconds").number(), TTL_SECONDS);
    assert_eq!(
        vector.input("channel_id").array(),
        config(K_CH).channel_id()
    );
}

/// The sender of a vector whose signature is valid, from its seed.
fn check_sender(vector: &Vector) -> SenderKey {
    let key = sender(vector.input("sender_seed").array());
    assert_eq!(
        key.public().0,
        vector.input("pk_u").array(),
        "{}",
        vector.name()
    );
    key
}

/// A positive vector built with `seal`: the payload, `mk`, `enc_hdr`, the
/// signature and the whole blob, which `verify` accepts (R1, R4, R16).
fn check_sealed(vector: &Vector) {
    check_channel(vector);
    let key = check_sender(vector);
    let counter = vector.input("counter").u64_hex();
    let nonce = Nonce(vector.input("nonce").array());
    if vector.name() == "text_k1" {
        assert_eq!(vector.input("sender_seed").array(), SENDER_SEED);
        assert_eq!((counter, nonce.0), (COUNTER, NONCE));
        assert_eq!(vector.input("sent_at").u64_hex(), SENT_AT);
        assert_eq!(vector.input("body").bytes(), BODY);
        assert_eq!(vector.input("received_at").u64_hex(), RECEIVED_AT);
        assert_eq!(vector.input("now").u64_hex(), NOW);
    }
    if vector.name() == "key_retired" {
        assert_eq!(counter, KEY_RETIRED_COUNTER, "ADR 0033");
    }
    let kind = match vector.input("type").number() {
        0 => PayloadKind::Text,
        1 => PayloadKind::KeyRetired,
        other => PayloadKind::Unknown(u8::try_from(other).unwrap()),
    };
    let payload = Payload {
        kind,
        display_name: None,
        sent_at: vector.input("sent_at").u64_hex(),
        body: vector.input("body").bytes().to_vec(),
    };
    assert_eq!(
        payload.encode().unwrap(),
        vector.expected("payload").bytes()
    );
    let ctx = ctx();
    let mk = message_key(&ctx.keys, key.public(), counter).unwrap();
    assert_eq!(mk.expose(), &vector.expected("mk").array());
    let Sealed { blob, signature } = seal(&ctx, &key, counter, &nonce, &payload).unwrap();
    assert_eq!(blob, vector.expected("blob").bytes(), "{}", vector.name());
    assert_eq!(blob[17..57], *vector.expected("enc_hdr").bytes());
    assert_eq!(signature, vector.expected("signature").array());
    let received_at = vector.input("received_at").u64_hex();
    let verified = verify(&blob, &ctx, received_at, vector.input("now").u64_hex()).unwrap();
    assert_eq!(verified.signature(), &signature);
    assert_eq!(vector.expected("content").text(), "message");
    let opened = verified.open().unwrap();
    assert_eq!(opened.sent_at, Some(payload.sent_at));
    assert_eq!(opened.content, Content::Message(payload));
}

/// A positive vector built with `seal_padded`: the blob, and what `open`
/// makes of it (R12).
fn check_opened(vector: &Vector) {
    check_channel(vector);
    let key = check_sender(vector);
    let ctx = ctx();
    let counter = vector.input("counter").u64_hex();
    let nonce = Nonce(vector.input("nonce").array());
    let mk = message_key(&ctx.keys, key.public(), counter).unwrap();
    assert_eq!(mk.expose(), &vector.expected("mk").array());
    let padded = vector.input("padded").bytes();
    let Sealed { blob, signature } = seal_padded(&ctx, &key, counter, &nonce, padded).unwrap();
    assert_eq!(blob, vector.expected("blob").bytes(), "{}", vector.name());
    assert_eq!(blob[17..57], *vector.expected("enc_hdr").bytes());
    assert_eq!(signature, vector.expected("signature").array());
    let received_at = vector.input("received_at").u64_hex();
    let now = vector.input("now").u64_hex();
    let opened = verify(&blob, &ctx, received_at, now)
        .unwrap()
        .open()
        .unwrap();
    let sent_at = vector
        .has_expected("sent_at")
        .then(|| vector.expected("sent_at").u64_hex());
    assert_eq!(opened.sent_at, sent_at, "{}", vector.name());
    let content = match &opened.content {
        Content::Message(payload) => {
            let kind = u8::try_from(vector.expected("type").number()).unwrap();
            let expected = Payload {
                kind: if kind == 0 {
                    PayloadKind::Text
                } else {
                    PayloadKind::KeyRetired
                },
                display_name: None,
                sent_at: sent_at.unwrap(),
                body: vector.expected("body").bytes().to_vec(),
            };
            assert_eq!(payload, &expected, "{}", vector.name());
            "message"
        }
        Content::Unreadable => "unreadable",
        Content::Stale => "stale",
    };
    assert_eq!(
        content,
        vector.expected("content").text(),
        "{}",
        vector.name()
    );
}

/// `aead_forged_signed`: `verify` accepts the signature and `open` refuses
/// the ciphertext (R12).
fn check_forged(vector: &Vector) {
    check_channel(vector);
    check_sender(vector);
    let ctx = ctx();
    let blob = vector.input("blob").bytes();
    let received_at = vector.input("received_at").u64_hex();
    let verified = verify(blob, &ctx, received_at, vector.input("now").u64_hex()).unwrap();
    let error = format!("{:?}", verified.open().expect_err("a forged ciphertext"));
    assert_eq!(error, vector.expected("error").text());
}

/// A negative vector: `verify` returns its error; when it carries a signer,
/// the unmasked signature verifies over the range the vector names.
fn check_rejected(vector: &Vector) {
    check_channel(vector);
    let blob = vector.input("blob").bytes();
    let ctx = ctx();
    let received_at = vector.input("received_at").u64_hex();
    let verdict = verify(blob, &ctx, received_at, vector.input("now").u64_hex());
    let error = format!("{:?}", verdict.err().expect("a rejected blob"));
    assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
    check_edit(vector.name(), blob);
    if vector.has_input("pk_u") {
        let key = check_sender(vector);
        let stream = header_keystream(&ctx.keys, &Nonce(blob[57..81].try_into().unwrap())).unwrap();
        let (signed, masked) = blob.split_at(blob.len() - 64);
        let signature = xor(masked.try_into().unwrap(), stream[40..].try_into().unwrap());
        let start = if vector.name() == "signed_ciphertext_only" {
            HEADER_LEN
        } else {
            0
        };
        let message = [MSG_SIGNATURE_TAG.as_slice(), &signed[start..]].concat();
        let signature = crypto::Signature(signature);
        assert!(crypto::verify_detached(key.public(), &message, &signature).is_ok());
    }
}

/// The edits a negative vector's name promises (T08, T22): a `mutate_*`
/// differs from `text_k1` in one byte of its region, and
/// `signed_ciphertext_only` opens to the header of `text_k1` with its lowest
/// counter bit flipped.
fn check_edit(name: &str, blob: &[u8]) {
    let original = sealed().blob;
    let last = original.len() - 1;
    let region = match name {
        "mutate_version" => 0..1,
        "mutate_channel_id" => 1..17,
        "mutate_enc_hdr" => 17..57,
        "mutate_nonce" => 57..81,
        "mutate_ciphertext" => HEADER_LEN..last + 1 - 64,
        "mutate_signature" => last + 1 - 64..last + 1,
        "signed_ciphertext_only" => {
            let stream = header_keystream(&ctx().keys, &Nonce(NONCE)).unwrap();
            let header = Header::from_bytes(&xor(
                blob[17..57].try_into().unwrap(),
                stream[..40].try_into().unwrap(),
            ));
            assert_eq!(header.sender_pk.0, sender(SENDER_SEED).public().0);
            assert_eq!(header.counter, COUNTER ^ 1);
            return;
        }
        _ => return,
    };
    let changed: Vec<usize> = (0..original.len())
        .filter(|&offset| blob[offset] != original[offset])
        .collect();
    assert_eq!(changed.len(), 1, "{name}");
    assert!(region.contains(&changed[0]), "{name}");
}

/// Spec 015, R3: every vector of `013.json` is checked once.
#[test]
fn s013_vectors_dispatch() {
    let sealed = ["text_k1", "text_k63", "key_retired"];
    let rejected = [
        "expired_received_at",
        "mutate_version",
        "mutate_channel_id",
        "mutate_enc_hdr",
        "mutate_nonce",
        "mutate_ciphertext",
        "mutate_signature",
        "signed_ciphertext_only",
        "short_blob",
        "long_blob",
        "unaligned_blob",
    ];
    let opened = [
        "unknown_payload_key",
        "unknown_type",
        "bad_padding",
        "bad_payload_record",
        "missing_sent_at",
        "sent_at_not_a_minute",
        "display_name_too_long",
        "display_name_control",
        "display_name_not_utf8",
        "display_name_in_key_retired",
        "stale_sent_at",
        "stale_unknown_type",
        "stale_missing_type",
        "stale_trailing_garbage",
        "future_sent_at",
    ];
    let entries = [
        sealed
            .map(|name| (name, check_sealed as Checker))
            .as_slice(),
        rejected
            .map(|name| (name, check_rejected as Checker))
            .as_slice(),
        opened
            .map(|name| (name, check_opened as Checker))
            .as_slice(),
        &[("aead_forged_signed", check_forged as Checker)],
    ]
    .concat();
    vectors::check_all("013", &entries);
}
