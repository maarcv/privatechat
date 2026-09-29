//! Tests of spec 017 over records built by hand, byte by byte, so that each
//! one breaks exactly the rule it names.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, proptest};

use super::test_schema::{MAX_BYTES, MAX_RECORD, MAX_TEXT, TestRecord};
use super::{FIELD_HEADER_LEN, Reader, RecordError, UnknownKeys, Writer};
use crate::vectors::{self, Checker, Kind, Vector};

use RecordError::{KeyOrder, Missing, TooLong, Truncated, UnknownKey, Utf8, Width};
use UnknownKeys::{Ignore, Reject};

const POLICIES: [UnknownKeys; 2] = [Ignore, Reject];

/// The fields of a hand-built record, in the order the test chooses.
type Fields<'a> = &'a [(u8, &'a [u8])];

/// One field: key ‖ 4-byte big-endian length ‖ value (R1).
fn field(key: u8, value: &[u8]) -> Vec<u8> {
    let len = u32::try_from(value.len()).unwrap();
    [&[key][..], &len.to_be_bytes(), value].concat()
}

/// The fields in the order given, which the test chooses.
fn record(fields: Fields) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|(key, value)| field(*key, value))
        .collect()
}

/// The test schema's verdict on `buf`: `None` when it decodes.
fn error(buf: &[u8], policy: UnknownKeys) -> Option<RecordError> {
    TestRecord::decode(buf, policy).err()
}

/// Reads keys 0 and 5 only, so that a key between them is read past rather
/// than reached by `end`: with the full test schema an unknown key is above 5
/// and never sits between two known ones.
fn read_0_and_5(buf: &[u8], policy: UnknownKeys) -> Option<RecordError> {
    let mut reader = Reader::new(buf, MAX_RECORD, policy).unwrap();
    let read = reader.u8(0).and_then(|_| reader.text(5, MAX_TEXT));
    read.and_then(|_| reader.end()).err()
}

/// Spec 017, R1: a field is key ‖ 4-byte big-endian length ‖ value, and a
/// record of no fields is zero bytes. The same bytes as the vectors
/// `u8_field` and `empty_record`, which only `s017_vectors_dispatch` loads.
#[test]
fn s017_t01_r01_field_framing() {
    let u8_field = [0x00, 0x00, 0x00, 0x00, 0x01, 0x2a];
    let decoded = TestRecord::decode(&u8_field, Reject).unwrap();
    assert_eq!(decoded.small, 0x2a);
    assert_eq!(decoded.encode().unwrap().as_slice(), u8_field);
    assert_eq!(Writer::with_capacity(0).finish().as_slice(), []);
    assert_eq!(error(&[], Reject), Some(Missing));
}

/// Spec 017, R2: key order is checked after the framing and before the
/// unknown-key policy.
#[test]
fn s017_t02_r02_field_check_order() {
    let lower = record(&[(0, &[1]), (2, &[0; 8]), (1, &[0; 4])]);
    let repeated = record(&[(0, &[1]), (1, &[0; 4]), (1, &[0; 4])]);
    // Key 2 after key 3, with a length of 9 and one byte left.
    let truncated = [record(&[(0, &[1]), (3, b"ab")]), vec![2, 0, 0, 0, 9, 0]].concat();
    // Key 3 is unknown to `read_0_and_5` and comes after key 5.
    let unknown = record(&[(0, &[1]), (5, b"y"), (3, b"x")]);
    for policy in POLICIES {
        assert_eq!(error(&lower, policy), Some(KeyOrder));
        assert_eq!(error(&repeated, policy), Some(KeyOrder));
        assert_eq!(error(&truncated, policy), Some(Truncated));
        assert_eq!(read_0_and_5(&unknown, policy), Some(KeyOrder));
    }
    // A schema that asks out of order gets an error, not a silent `None`.
    let buf = record(&[(0, &[1]), (3, b"ab")]);
    let mut reader = Reader::new(&buf, MAX_RECORD, Ignore).unwrap();
    assert_eq!(reader.bytes(3, MAX_BYTES), Ok(Some(&b"ab"[..])));
    assert_eq!(reader.bytes(3, MAX_BYTES), Err(KeyOrder));
    assert_eq!(reader.bytes(2, MAX_BYTES), Err(KeyOrder));
}

/// Spec 017, R3: integers are exactly 1, 4 or 8 bytes, big-endian.
#[test]
fn s017_t03_r03_integer_widths() {
    let cases: [Fields; 6] = [
        &[(0, &[])],
        &[(0, &[1, 2])],
        &[(0, &[1]), (1, &[0; 3])],
        &[(0, &[1]), (1, &[0; 5])],
        &[(0, &[1]), (2, &[0; 7])],
        &[(0, &[1]), (2, &[0; 9])],
    ];
    for fields in cases {
        assert_eq!(error(&record(fields), Reject), Some(Width), "{fields:?}");
    }
    let maxima = record(&[(0, &[0xff]), (1, &[0xff; 4]), (2, &[0xff; 8])]);
    let decoded = TestRecord::decode(&maxima, Reject).unwrap();
    assert_eq!(decoded.small, u8::MAX);
    assert_eq!(decoded.medium, Some(u32::MAX));
    assert_eq!(decoded.large, Some(u64::MAX));
    assert_eq!(decoded.encode().unwrap().as_slice(), maxima);
    let big_endian = record(&[(0, &[0]), (1, &[1, 2, 3, 4])]);
    let decoded = TestRecord::decode(&big_endian, Reject).unwrap();
    assert_eq!(decoded.medium, Some(0x0102_0304));
}

/// Spec 017, R4: `bytesN` is exact, `bytes` and `text` are bounded, and
/// `text` is UTF-8.
#[test]
fn s017_t04_r04_bytes_and_text_limits() {
    let longest = vec![b'a'; MAX_BYTES];
    let accepted = record(&[(0, &[1]), (3, &longest), (5, &longest[..MAX_TEXT])]);
    let decoded = TestRecord::decode(&accepted, Reject).unwrap();
    assert_eq!(decoded.bytes, Some(&longest[..]));
    assert_eq!(decoded.text.map(str::len), Some(MAX_TEXT));
    let too_long = vec![b'a'; MAX_BYTES + 1];
    // Too long and not UTF-8: the length is checked first.
    let both = vec![0xff; MAX_TEXT + 1];
    let cases: [(Fields, RecordError); 6] = [
        (&[(0, &[1]), (4, &[0; 31])], Width),
        (&[(0, &[1]), (4, &[0; 33])], Width),
        (&[(0, &[1]), (3, &too_long)], TooLong),
        (&[(0, &[1]), (5, &too_long)], TooLong),
        (&[(0, &[1]), (5, &both)], TooLong),
        (&[(0, &[1]), (5, &[b'a', 0xff])], Utf8),
    ];
    for (fields, expected) in cases {
        assert_eq!(error(&record(fields), Reject), Some(expected), "{fields:?}");
    }
}

/// Spec 017, R5: `end` frames whatever is left and applies the policy to it.
#[test]
fn s017_t05_r05_end_walks_the_rest() {
    let valid = record(&[(0, &[1]), (5, b"hi")]);
    let extra_byte = [&valid[..], &[0]].concat();
    let extra_field = [valid, field(9, b"x")].concat();
    // `end` keeps walking after a field it skipped.
    let skipped_then_extra_byte = [&extra_field[..], &[0]].concat();
    for policy in POLICIES {
        assert_eq!(error(&extra_byte, policy), Some(Truncated));
    }
    assert_eq!(error(&skipped_then_extra_byte, Ignore), Some(Truncated));
    assert_eq!(error(&extra_field, Reject), Some(UnknownKey));
    assert_eq!(error(&extra_field, Ignore), None);
}

/// Spec 017, R6: an absent optional key is `None`; an absent mandatory key is
/// `Missing`.
#[test]
fn s017_t06_r06_missing_and_optional() {
    let only_mandatory = record(&[(0, &[7])]);
    let decoded = TestRecord::decode(&only_mandatory, Reject).unwrap();
    let empty = TestRecord {
        small: 7,
        medium: None,
        large: None,
        bytes: None,
        bytes32: None,
        text: None,
    };
    assert_eq!(decoded, empty);
    let without_key_0 = record(&[(1, &[0; 4])]);
    for policy in POLICIES {
        assert_eq!(error(&[], policy), Some(Missing));
        assert_eq!(error(&without_key_0, policy), Some(Missing));
    }
}

/// Spec 017, R7: the policy applies to every field walked, by a getter or by
/// `end`.
#[test]
fn s017_t07_r07_unknown_key_policy() {
    let read_past = record(&[(0, &[1]), (3, b"x"), (5, b"y")]);
    let reached_by_end = record(&[(0, &[1]), (5, b"y"), (6, b"x")]);
    for buf in [read_past, reached_by_end] {
        assert_eq!(read_0_and_5(&buf, Ignore), None);
        assert_eq!(read_0_and_5(&buf, Reject), Some(UnknownKey));
    }
    // The key after a skipped one is still read.
    let buf = record(&[(0, &[1]), (3, b"x"), (5, b"y")]);
    let mut reader = Reader::new(&buf, MAX_RECORD, Ignore).unwrap();
    assert_eq!(reader.u8(0), Ok(Some(1)));
    assert_eq!(reader.text(5, MAX_TEXT), Ok(Some("y")));
    assert_eq!(reader.end(), Ok(()));
}

/// Spec 017, R8: the whole-record limit is checked before any field, so even
/// bytes that would not frame return `TooLong`.
#[test]
fn s017_t08_r08_whole_record_limit() {
    assert_eq!((MAX_RECORD, MAX_BYTES, MAX_TEXT), (512, 64, 64));
    let head = record(&[(0, &[1])]);
    let filler = vec![0; MAX_RECORD - head.len() - FIELD_HEADER_LEN];
    let fits = [head, field(6, &filler)].concat();
    assert_eq!(fits.len(), MAX_RECORD);
    assert_eq!(error(&fits, Ignore), None);
    assert_eq!(error(&[&fits[..], &[0]].concat(), Ignore), Some(TooLong));
    let garbage = vec![0xff; MAX_RECORD + 1];
    assert_eq!(
        Reader::new(&garbage, MAX_RECORD, Reject).err(),
        Some(TooLong)
    );
}

/// Spec 017, R9: each key lands in its own field of the struct, and a value
/// shaped like a record stays bytes.
#[test]
fn s017_t09_r09_test_schema_is_typed() {
    let nested = record(&[(0, &[2]), (1, &[0; 4])]);
    let buf = record(&[
        (0, &[1]),
        (1, &[0, 0, 0, 2]),
        (2, &[0, 0, 0, 0, 0, 0, 0, 3]),
        (3, &nested),
        (4, &[4; 32]),
        (5, "é \t".as_bytes()),
    ]);
    let decoded = TestRecord::decode(&buf, Reject).unwrap();
    let expected = TestRecord {
        small: 1,
        medium: Some(2),
        large: Some(3),
        bytes: Some(&nested),
        bytes32: Some(&[4; 32]),
        text: Some("é \t"),
    };
    assert_eq!(decoded, expected);
}

/// Spec 017, R11: the writer allocates its capacity once and refuses to grow
/// or to go back on the key order.
#[test]
fn s017_t11_r11_writer_never_grows() {
    let mut writer = Writer::with_capacity(20);
    writer.u64(1, u64::MAX).unwrap();
    assert_eq!(writer.u8(1, 0), Err(KeyOrder));
    assert_eq!(writer.u8(0, 0), Err(KeyOrder));
    assert_eq!(writer.bytes(2, &[0; 3]), Err(TooLong));
    writer.bytes(2, &[0; 2]).unwrap();
    assert_eq!(writer.text(3, ""), Err(TooLong));
    let buf = writer.finish();
    assert_eq!((buf.len(), buf.capacity()), (20, 20));
    // Zeroed pages are mapped lazily: this allocates no 4 GiB in practice.
    #[cfg(target_pointer_width = "64")]
    {
        let huge = vec![0u8; 1 << 32];
        assert_eq!(Writer::with_capacity(16).bytes(1, &huge), Err(TooLong));
    }
}

/// Checks one vector of `017.json`: a positive decodes to its values and,
/// under `reject`, encodes back to its bytes; a negative returns its error.
fn check_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "test");
    let policy = match vector.input("policy").text() {
        "reject" => Some(Reject),
        "ignore" => Some(Ignore),
        _ => None,
    }
    .expect("a policy of spec 017");
    let record = vector.input("record").bytes();
    let decoded = TestRecord::decode(record, policy);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.unwrap_err());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        return;
    }
    let optional = |field| vector.has_expected(field).then(|| vector.expected(field));
    let expected = TestRecord {
        small: u8::try_from(vector.expected("small").number()).unwrap(),
        medium: optional("medium").map(|value| value.number()),
        large: optional("large").map(|value| value.u64_hex()),
        bytes: optional("bytes").map(|value| value.bytes()),
        bytes32: optional("bytes32").map(|value| value.bytes().try_into().unwrap()),
        text: optional("text").map(|value| core::str::from_utf8(value.bytes()).unwrap()),
    };
    let decoded = decoded.unwrap();
    assert_eq!(decoded, expected, "{}", vector.name());
    if policy == Reject {
        assert_eq!(
            decoded.encode().unwrap().as_slice(),
            record,
            "{}",
            vector.name()
        );
    }
}

/// Spec 015, R3: every vector of `017.json` is checked once, by `check_vector`.
#[test]
fn s017_vectors_dispatch() {
    let names = [
        "empty_record",
        "u8_field",
        "u32_field",
        "u64_field",
        "bytes_field",
        "bytes32_field",
        "text_field",
        "all_fields",
        "unknown_key_ignored",
        "record_at_limit",
        "key_out_of_order",
        "duplicate_key",
        "u32_wrong_width",
        "bytes32_wrong_width",
        "bytes_too_long",
        "text_too_long",
        "record_too_long",
        "truncated_length",
        "length_beyond_buffer",
        "extra_byte",
        "unknown_key_then_extra_byte",
        "invalid_utf8",
        "unknown_key_rejected",
    ];
    vectors::check_all("017", &names.map(|name| (name, check_vector as Checker)));
}

proptest! {
    /// Spec 017, R10: decode(encode(x)) = x over the test schema, and a
    /// one-byte change of an encoding that still decodes under `reject`
    /// encodes back to the changed bytes.
    #[test]
    fn s017_t10_r10_round_trip(
        small in any::<u8>(),
        medium in maybe(any::<u32>()),
        large in maybe(any::<u64>()),
        bytes in maybe(bytes_of(any::<u8>(), 0..=MAX_BYTES)),
        bytes32 in maybe(any::<[u8; 32]>()),
        // 16 characters of at most 4 UTF-8 bytes each stay within MAX_TEXT.
        text in maybe("[\\PC\\s]{0,16}"),
        flip in any::<(usize, u8)>(),
    ) {
        let record = TestRecord {
            small,
            medium,
            large,
            bytes: bytes.as_deref(),
            bytes32: bytes32.as_ref(),
            text: text.as_deref(),
        };
        let encoded = record.encode().unwrap();
        assert_eq!(TestRecord::decode(&encoded, Reject).unwrap(), record);
        let mut changed = encoded.to_vec();
        let at = flip.0 % changed.len();
        changed[at] ^= flip.1;
        if let Ok(decoded) = TestRecord::decode(&changed, Reject) {
            assert_eq!(decoded.encode().unwrap().as_slice(), changed);
        }
    }

    /// Spec 017, R12: any buffer decodes to a value or a `RecordError`, never
    /// a panic, under both policies.
    #[test]
    fn s017_t12_r12_arbitrary_bytes_never_panic(buf in bytes_of(any::<u8>(), 0..=4096)) {
        for policy in POLICIES {
            let _ = error(&buf, policy);
        }
    }

    /// Spec 017, R12: the same over well-framed fields with random keys and
    /// lengths, which random bytes almost never produce.
    #[test]
    fn s017_t12_r12_framed_fields_never_panic(
        fields in bytes_of((any::<u8>(), bytes_of(any::<u8>(), 0..=40)), 0..=12),
    ) {
        let buf: Vec<u8> = fields.iter().flat_map(|(key, value)| field(*key, value)).collect();
        for policy in POLICIES {
            let _ = error(&buf, policy);
        }
    }
}
