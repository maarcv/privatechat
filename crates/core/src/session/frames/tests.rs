//! Tests of spec 028 R1–R3 at the level of the codec: the schemas, the
//! version rule and the round trip. The clauses that need a `Session` (the
//! `Reconnect` and `UnsupportedServer` events) are in the session's tests.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{Strategy, any, prop_oneof, proptest};

use super::{Frame, MAX_FRAME, is_supported};
use crate::Error;
use crate::storage::state::items::MAX_BLOB;
use crate::vectors::{self, Checker, Kind, Value, Vector};

/// One frame of each type, every optional key present.
fn references() -> Vec<Frame> {
    vec![
        Frame::Hello {
            server_nonce: [1; 32],
            proto_versions: vec![1],
        },
        Frame::Subscribe {
            pk_ch: [2; 32],
            ttl_seconds: 86_400,
            sig: [3; 64],
            since: Some(60_000),
        },
        Frame::Ok {
            channel_id: [4; 16],
        },
        Frame::Publish {
            channel_id: [4; 16],
            client_ref: [5; 16],
            blob: vec![6; 1_185],
        },
        Frame::Ack {
            client_ref: [5; 16],
            server_id: [7; 16],
            received_at: 120_000,
        },
        Frame::Push {
            channel_id: [4; 16],
            server_id: [7; 16],
            received_at: 120_000,
            blob: vec![6; 1_185],
        },
        Frame::Error {
            code: "bad_blob".to_owned(),
            message: "rejected".to_owned(),
            channel_id: Some([4; 16]),
            client_ref: Some([5; 16]),
        },
    ]
}

/// The fields of a record as `(key, value)`, in order.
fn fields(record: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut rest = record;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        fields.push((rest[0], rest[5..5 + len].to_vec()));
        rest = &rest[5 + len..];
    }
    fields
}

/// The record of these fields.
fn record(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut record = Vec::new();
    for (key, value) in fields {
        record.push(*key);
        record.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        record.extend_from_slice(value);
    }
    record
}

/// The encoding of `decode(bytes)`.
fn reencoded(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    Frame::decode(bytes)?.encode()
}

/// Spec 028, R1: each frame round-trips; a frame above 70 000 bytes, an
/// unknown `type`, a missing mandatory key, a value of the wrong width and
/// a `code` of 33 bytes are refused; an unknown key is ignored. Optional
/// keys may be left out. `encode` refuses what `decode` would.
#[test]
fn s028_t01_r01_frame_schemas() {
    // Keys 1 and up that a frame of each `type` may leave out.
    let optional: [&[u8]; 7] = [&[], &[4], &[], &[], &[], &[], &[3, 4]];
    for (frame, optional) in references().iter().zip(optional) {
        let bytes = frame.encode().unwrap();
        assert_eq!(reencoded(&bytes), Ok(bytes.clone()), "{frame:?}");
        let fields = fields(&bytes);
        for (index, (key, value)) in fields.iter().enumerate().skip(1) {
            let mut without = fields.clone();
            without.remove(index);
            let decoded = Frame::decode(&record(&without));
            assert_eq!(
                decoded.is_ok(),
                optional.contains(key),
                "{frame:?} without {key}"
            );
            if value.len() > 1 {
                // One byte short: a fixed width broken, or a blob or text
                // that still fits; never a panic.
                let mut short = fields.clone();
                short[index].1.pop();
                let _ = Frame::decode(&record(&short));
            }
        }
        // An unknown key, before the end and after it, is ignored.
        let mut extended = fields.clone();
        extended.push((200, vec![9; 3]));
        assert_eq!(reencoded(&record(&extended)), Ok(bytes.clone()));
        let mut without_type = fields.clone();
        without_type.remove(0);
        assert_eq!(
            Frame::decode(&record(&without_type)).err(),
            Some(Error::BadPayload)
        );
    }
    let ok = Frame::Ok {
        channel_id: [4; 16],
    }
    .encode()
    .unwrap();
    // At the limit with an unknown key as filler, and one byte over it.
    let filler = MAX_FRAME - ok.len() - 5;
    let at_limit = record(&[fields(&ok), vec![(9, vec![0; filler])]].concat());
    assert_eq!(at_limit.len(), MAX_FRAME);
    assert_eq!(reencoded(&at_limit), Ok(ok.clone()));
    let over = record(&[fields(&ok), vec![(9, vec![0; filler + 1])]].concat());
    assert_eq!(over.len(), 70_001);
    assert_eq!(Frame::decode(&over).err(), Some(Error::BadPayload));

    let broken = [
        record(&[(0, vec![7])]),
        record(&[(0, vec![2])]),
        record(&[(0, vec![2]), (1, vec![4; 15])]),
        record(&[(0, vec![2, 0]), (1, vec![4; 16])]),
        record(&[(0, vec![0]), (1, vec![1; 32]), (2, vec![0, 0, 0, 2, 1, 1])]),
        record(&[(0, vec![0]), (1, vec![1; 32]), (2, vec![0, 0, 0, 0])]),
        record(&[
            (0, vec![4]),
            (1, vec![5; 16]),
            (2, vec![7; 16]),
            (3, vec![0; 7]),
        ]),
        record(&[(0, vec![6]), (1, vec![b'c'; 33]), (2, vec![])]),
        record(&[(0, vec![6]), (1, vec![]), (2, vec![b'm'; 257])]),
        record(&[(0, vec![6]), (1, vec![0xff]), (2, vec![])]),
        record(&[
            (0, vec![5]),
            (1, vec![4; 16]),
            (2, vec![7; 16]),
            (3, vec![0; 8]),
            (4, vec![0; MAX_BLOB + 1]),
        ]),
        record(&[(1, vec![4; 16]), (0, vec![2])]),
        ok[..ok.len() - 1].to_vec(),
    ];
    for bytes in &broken {
        assert_eq!(
            Frame::decode(bytes).err(),
            Some(Error::BadPayload),
            "{bytes:02x?}"
        );
    }
    let at_bounds = [
        record(&[(0, vec![6]), (1, vec![b'c'; 32]), (2, vec![b'm'; 256])]),
        record(&[
            (0, vec![5]),
            (1, vec![4; 16]),
            (2, vec![7; 16]),
            (3, vec![0; 8]),
            (4, vec![0; MAX_BLOB]),
        ]),
    ];
    for bytes in &at_bounds {
        assert_eq!(reencoded(bytes).as_deref(), Ok(bytes.as_slice()));
    }

    let too_long = [
        Frame::Error {
            code: "c".repeat(33),
            message: String::new(),
            channel_id: None,
            client_ref: None,
        },
        Frame::Error {
            code: String::new(),
            message: "m".repeat(257),
            channel_id: None,
            client_ref: None,
        },
        Frame::Publish {
            channel_id: [4; 16],
            client_ref: [5; 16],
            blob: vec![0; MAX_BLOB + 1],
        },
        Frame::Push {
            channel_id: [4; 16],
            server_id: [7; 16],
            received_at: 0,
            blob: vec![0; MAX_BLOB + 1],
        },
        Frame::Hello {
            server_nonce: [1; 32],
            proto_versions: vec![1; MAX_FRAME],
        },
    ];
    for frame in &too_long {
        assert_eq!(frame.encode().err(), Some(Error::BadPayload));
    }
}

/// Spec 028, R2: `proto_versions` is bounded by the frame alone, and the
/// session takes 1 to 8 items with 1 among them.
#[test]
fn s028_t02_r02_version_list() {
    let nine: Vec<u8> = (1..=9).collect();
    let eight: Vec<u8> = (1..=8).collect();
    let cases: [(&[u8], bool); 7] = [
        (&[1], true),
        (&[2, 1], true),
        (&eight, true),
        (&[], false),
        (&[2], false),
        (&nine, false),
        (&[0; 8], false),
    ];
    for (versions, supported) in cases {
        assert_eq!(is_supported(versions), supported, "{versions:?}");
    }
    // 13 000 items of 5 bytes each still decode; the session refuses them.
    let many = Frame::Hello {
        server_nonce: [1; 32],
        proto_versions: vec![1; 13_000],
    };
    let decoded = Frame::decode(&many.encode().unwrap()).unwrap();
    assert!(matches!(
        &decoded,
        Frame::Hello { proto_versions, .. }
            if proto_versions.len() == 13_000 && !is_supported(proto_versions)
    ));
}

fn bytes64() -> impl Strategy<Value = [u8; 64]> {
    (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(a, b)| {
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(&a);
        sig[32..].copy_from_slice(&b);
        sig
    })
}

/// Any frame `encode` accepts.
fn frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        (any::<[u8; 32]>(), bytes_of(any::<u8>(), 0..=16)).prop_map(
            |(server_nonce, proto_versions)| Frame::Hello {
                server_nonce,
                proto_versions,
            }
        ),
        (
            any::<[u8; 32]>(),
            any::<u32>(),
            bytes64(),
            maybe(any::<u64>())
        )
            .prop_map(|(pk_ch, ttl_seconds, sig, since)| Frame::Subscribe {
                pk_ch,
                ttl_seconds,
                sig,
                since,
            }),
        any::<[u8; 16]>().prop_map(|channel_id| Frame::Ok { channel_id }),
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            bytes_of(any::<u8>(), 0..=2_048)
        )
            .prop_map(|(channel_id, client_ref, blob)| Frame::Publish {
                channel_id,
                client_ref,
                blob,
            }),
        (any::<[u8; 16]>(), any::<[u8; 16]>(), any::<u64>()).prop_map(
            |(client_ref, server_id, received_at)| Frame::Ack {
                client_ref,
                server_id,
                received_at,
            }
        ),
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            any::<u64>(),
            bytes_of(any::<u8>(), 0..=2_048)
        )
            .prop_map(|(channel_id, server_id, received_at, blob)| Frame::Push {
                channel_id,
                server_id,
                received_at,
                blob,
            }),
        // 8 and 64 characters of at most 4 UTF-8 bytes stay within 32 and 256.
        (
            "\\PC{0,8}",
            "\\PC{0,64}",
            maybe(any::<[u8; 16]>()),
            maybe(any::<[u8; 16]>())
        )
            .prop_map(|(code, message, channel_id, client_ref)| Frame::Error {
                code,
                message,
                channel_id,
                client_ref,
            }),
    ]
}

proptest! {
    /// Spec 028, R3: `encode(decode(encode(f))) = encode(f)` for every frame.
    #[test]
    fn s028_t03_r03_frames_round_trip_and_fuzz(frame in frame()) {
        let bytes = frame.encode().unwrap();
        assert_eq!(reencoded(&bytes), Ok(bytes));
    }
}

/// Spec 028, R3: the fuzz checker requires the target `frame_decode`.
#[test]
fn s028_t03_r03_frame_decode_target_listed() {
    let checker = include_str!("../../../../../scripts/check_fuzz_targets.py");
    assert!(checker.contains("\"frame_decode\""));
}

/// The vector names of keys 1 and up, by `type` (the table "Frames").
const FIELD_NAMES: [&[&str]; 7] = [
    &["server_nonce", "proto_versions"],
    &["pk_ch", "ttl_seconds", "sig", "since"],
    &["channel_id"],
    &["channel_id", "client_ref", "blob"],
    &["client_ref", "server_id", "received_at"],
    &["channel_id", "server_id", "received_at", "blob"],
    &["code", "message", "channel_id", "client_ref"],
];

/// The encoded value of an expected field: bytes as they are (a `u64` is
/// its 8 bytes), a number as a `u32`, a list of numbers as `u8` items.
fn value_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::Hex(bytes) => bytes.clone(),
        Value::Number(number) => number.to_be_bytes().to_vec(),
        Value::List(items) => items
            .iter()
            .flat_map(|item| [0, 0, 0, 1, u8::try_from(item.number()).unwrap()])
            .collect(),
        // No frame field holds any other kind: the comparison fails.
        other => format!("{other:?}").into_bytes(),
    }
}

/// Checks a vector of `028.json`: `frame_type` is the byte at key 0; a
/// positive holds exactly its expected fields, decodes and, but for an
/// unknown key, encodes back to its bytes, so that every field went through
/// the decoder; a `hello` meets R2 as its `event` says; a negative is
/// `BadPayload`, which the session turns into `Reconnect`.
fn check_vector(vector: &Vector) {
    let bytes = vector.input("frame").bytes();
    let frame_type = vector.input("frame_type").number();
    let fields = fields(bytes);
    assert_eq!(fields[0], (0, vec![u8::try_from(frame_type).unwrap()]));
    let decoded = Frame::decode(bytes);
    let event = vector
        .has_expected("event")
        .then(|| vector.expected("event").text());
    if vector.kind() == Kind::Negative {
        assert_eq!(decoded.err(), Some(Error::BadPayload), "{}", vector.name());
        assert_eq!(vector.expected("error").text(), "BadPayload");
        assert_eq!(event, Some("reconnect"));
        return;
    }
    let names = FIELD_NAMES[usize::try_from(frame_type).unwrap()];
    let known: Vec<_> = fields[1..]
        .iter()
        .filter(|(key, _)| usize::from(*key) <= names.len())
        .collect();
    for (key, value) in &known {
        let expected = vector.expected(names[usize::from(*key) - 1]);
        assert_eq!(&value_bytes(expected), value, "{} key {key}", vector.name());
    }
    let expected_fields = names
        .iter()
        .filter(|name| vector.has_expected(name))
        .count();
    assert_eq!(expected_fields, known.len(), "{}", vector.name());
    let frame = decoded.unwrap();
    let encoded = frame.encode().unwrap();
    let unknown_key = vector.name() == "ok_unknown_key";
    assert_eq!(
        encoded,
        if unknown_key {
            &bytes[..encoded.len()]
        } else {
            bytes
        },
        "{}",
        vector.name()
    );
    if let Frame::Hello { proto_versions, .. } = &frame {
        assert!(matches!(event, Some("accepted" | "unsupported_server")));
        assert_eq!(is_supported(proto_versions), event == Some("accepted"));
    } else {
        assert_eq!(
            event,
            unknown_key.then_some("accepted"),
            "{}",
            vector.name()
        );
    }
}

/// Spec 015, R3: every vector of `028.json` is checked once.
#[test]
fn s028_vectors_dispatch() {
    let names = [
        "hello_reference",
        "subscribe_reference",
        "ok_reference",
        "publish_reference",
        "ack_reference",
        "push_reference",
        "error_reference",
        "hello_nine_versions",
        "hello_no_version",
        "hello_without_1",
        "ok_unknown_key",
        "type_unknown",
        "ok_missing_channel_id",
        "error_code_too_long",
    ];
    let entries: Vec<(&str, Checker)> = names
        .iter()
        .map(|name| (*name, check_vector as Checker))
        .collect();
    vectors::check_all("028", &entries);
}
