//! Tests of spec 013 R6–R10 and R14: the payload record, its one validation,
//! the name filter and the padding. The blob-level halves of T12–T14 are in
//! `envelope/tests.rs`.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{Just, Strategy, any, prop_oneof, proptest};

use super::{MAX_BLOCKS, MAX_DISPLAY_NAME, MAX_PAYLOAD, PAD_BLOCK, Payload, PayloadKind};
use crate::Error;
use crate::crypto;

use PayloadKind::{KeyRetired, Text, Unknown};

/// A whole minute, as every `sent_at` of a valid payload (R8).
const SENT_AT: u64 = 1_700_000_040_000;

fn text(body: &[u8], display_name: Option<&str>) -> Payload {
    Payload {
        kind: Text,
        display_name: display_name.map(str::to_owned),
        sent_at: SENT_AT,
        body: body.to_vec(),
    }
}

fn key_retired() -> Payload {
    Payload {
        kind: KeyRetired,
        display_name: None,
        sent_at: SENT_AT,
        body: Vec::new(),
    }
}

/// A record of the fields given, in the order given, which the test chooses.
fn record(fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in fields {
        out.push(*key);
        out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// A `text` whose encoding is exactly `len` bytes: 24 bytes of fields and
/// the rest body.
fn text_of_encoded_len(len: usize) -> Payload {
    text(&vec![b'a'; len - 24], None)
}

/// Spec 013, R6: the schema's keys and types, byte for byte; each missing
/// mandatory key, a `type` of two bytes and keys out of order fail; key 9
/// changes nothing.
#[test]
fn s013_t10_r06_payload_schema() {
    let sent_at = SENT_AT.to_be_bytes();
    let name = [0, 0, 0, 3, b'a', b'n', b'a'];
    let expected = [
        &[0, 0, 0, 0, 1, 0][..],
        &[1][..],
        &name,
        &[2, 0, 0, 0, 8],
        &sent_at,
        &[3, 0, 0, 0, 2, b'h', b'i'],
    ]
    .concat();
    let payload = text(b"hi", Some("ana"));
    assert_eq!(payload.encode().unwrap(), expected);
    assert_eq!(Payload::decode(&expected).unwrap(), payload);

    let broken: [&[(u8, &[u8])]; 5] = [
        &[(1, b"ana"), (2, &sent_at), (3, b"hi")],
        &[(0, &[0]), (3, b"hi")],
        &[(0, &[0]), (2, &sent_at)],
        &[(0, &[0, 0]), (2, &sent_at), (3, b"hi")],
        &[(0, &[0]), (3, b"hi"), (2, &sent_at)],
    ];
    for fields in broken {
        assert_eq!(
            Payload::decode(&record(fields)),
            Err(Error::BadPayload),
            "{fields:?}"
        );
    }
    let with_key_9 = record(&[(0, &[0]), (1, b"ana"), (2, &sent_at), (3, b"hi"), (9, b"x")]);
    assert_eq!(Payload::decode(&with_key_9).unwrap(), payload);
}

proptest! {
    /// Spec 013, R6: every payload `encode` writes decodes to itself, known
    /// types and unknown alike, as long as its name passes R9.
    #[test]
    fn s013_t10_r06_encode_decode_round_trip(
        kind in prop_oneof![Just(Text), (2u8..).prop_map(Unknown)],
        display_name in maybe("[a-zA-Z0-9 ]{0,64}"),
        sent_at in any::<u64>(),
        body in bytes_of(any::<u8>(), 0..2_048),
    ) {
        let payload = Payload { kind, display_name, sent_at, body };
        assert_eq!(Payload::decode(&payload.encode().unwrap()).unwrap(), payload);
    }
}

/// Spec 013, R7: each rule of `validate`, one case each, next to a valid
/// payload of each type.
#[test]
fn s013_t11_r07_validate_table() {
    assert_eq!(text(b"hi", Some("ana")).validate(), Ok(()));
    assert_eq!(key_retired().validate(), Ok(()));
    let long_name = "a".repeat(MAX_DISPLAY_NAME + 1);
    let cases = [
        (
            "unknown type",
            Payload {
                kind: Unknown(9),
                ..text(b"hi", None)
            },
        ),
        (
            "not a minute",
            Payload {
                sent_at: SENT_AT + 1,
                ..text(b"hi", None)
            },
        ),
        ("body not UTF-8", text(&[0xff], None)),
        (
            "key_retired body",
            Payload {
                body: b"x".to_vec(),
                ..key_retired()
            },
        ),
        (
            "key_retired name",
            Payload {
                display_name: Some("ana".into()),
                ..key_retired()
            },
        ),
        ("name too long", text(b"hi", Some(&long_name))),
        ("name with Cc", text(b"hi", Some("a\u{7f}"))),
        ("encoding too long", text_of_encoded_len(MAX_PAYLOAD + 1)),
    ];
    for (case, payload) in cases {
        assert_eq!(payload.validate(), Err(Error::BadPayload), "{case}");
    }
    assert_eq!(
        text(b"hi", Some(&"a".repeat(MAX_DISPLAY_NAME))).validate(),
        Ok(())
    );
    assert_eq!(text_of_encoded_len(MAX_PAYLOAD).validate(), Ok(()));
}

/// Spec 013, R8: `sent_at` must be a whole minute; zero is one.
#[test]
fn s013_t12_r08_sent_at_is_a_whole_minute() {
    for (sent_at, verdict) in [
        (60_001, Err(Error::BadPayload)),
        (60_000, Ok(())),
        (0, Ok(())),
    ] {
        assert_eq!(
            Payload {
                sent_at,
                ..text(b"hi", None)
            }
            .validate(),
            verdict,
            "{sent_at}"
        );
    }
}

/// Spec 013, R9: a name above 64 bytes, with a Cc character, not UTF-8, or
/// in a `key_retired` is dropped, and the rest of the payload decodes.
#[test]
fn s013_t13_r09_bad_display_name_is_dropped() {
    let sent_at = SENT_AT.to_be_bytes();
    let long_name = [b'a'; MAX_DISPLAY_NAME + 1];
    for (kind, name) in [
        (0, &long_name[..]),
        (0, b"a\tb"),
        (0, &[b'a', 0xff]),
        (1, b"ana"),
    ] {
        let body: &[u8] = if kind == 0 { b"hi" } else { b"" };
        let bytes = record(&[(0, &[kind]), (1, name), (2, &sent_at), (3, body)]);
        let payload = Payload::decode(&bytes).unwrap();
        assert_eq!(payload.display_name, None, "{name:?}");
        assert_eq!(payload.body, body);
        assert_eq!(payload.validate(), Ok(()));
    }
}

/// Spec 013, R10: padding makes 1 024·k with k in 1..=63, and nothing
/// larger encodes.
#[test]
fn s013_t14_r10_padding_sizes() {
    let smallest = text(b"", None).encode().unwrap();
    assert_eq!(smallest.len(), 24);
    for (mut encoded, blocks) in [
        (smallest, 1),
        (text_of_encoded_len(1_023).encode().unwrap(), 1),
        (text_of_encoded_len(1_024).encode().unwrap(), 2),
        (
            text_of_encoded_len(MAX_PAYLOAD).encode().unwrap(),
            MAX_BLOCKS,
        ),
    ] {
        crypto::pad(&mut encoded, PAD_BLOCK).unwrap();
        assert_eq!(encoded.len(), PAD_BLOCK * blocks);
    }
    let too_long = text_of_encoded_len(MAX_PAYLOAD + 1);
    assert_eq!(too_long.validate(), Err(Error::BadPayload));
    assert_eq!(too_long.encode(), Err(Error::BadPayload));
}

/// Spec 013, R14: the `Debug` of a payload shows neither its body nor its
/// name.
#[test]
fn s013_t18_r14_payload_debug_hides_content() {
    let debug = format!("{:?}", text(b"secret body", Some("secret name")));
    assert!(!debug.contains("secret"), "{debug}");
    assert!(debug.contains("[REDACTED]"), "{debug}");
}
