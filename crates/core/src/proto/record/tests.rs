//! Tests of spec 017 over records built by hand, byte by byte, so that each
//! one breaks exactly the rule it names.

use proptest::collection::vec as bytes_of;
use proptest::prelude::{any, proptest};

use super::test_schema::{MAX_BYTES, MAX_RECORD, MAX_TEXT, TestRecord};
use super::{Reader, RecordError, UnknownKeys};

use RecordError::{KeyOrder, Missing, TooLong, Truncated, UnknownKey, Utf8, Width};
use UnknownKeys::{Ignore, Reject};

const POLICIES: [UnknownKeys; 2] = [Ignore, Reject];

/// One field: key ‖ 4-byte big-endian length ‖ value (R1).
fn field(key: u8, value: &[u8]) -> Vec<u8> {
    let len = u32::try_from(value.len()).unwrap();
    [&[key][..], &len.to_be_bytes(), value].concat()
}

/// The fields in the order given, which the test chooses.
fn record(fields: &[(u8, &[u8])]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|(key, value)| field(*key, value))
        .collect()
}

/// The test schema's verdict on `buf`: `None` when it decodes.
fn error(buf: &[u8], unknown: UnknownKeys) -> Option<RecordError> {
    TestRecord::decode(buf, unknown).err()
}

/// Reads keys 0 and 5 only, so that a key between them is read past rather
/// than reached by `end`.
fn read_0_and_5(buf: &[u8], unknown: UnknownKeys) -> Option<RecordError> {
    let mut reader = Reader::new(buf, MAX_RECORD, unknown).unwrap();
    let read = reader.u8(0).and_then(|_| reader.text(5, MAX_TEXT));
    read.and_then(|_| reader.end()).err()
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
}

/// Spec 017, R3: integers are exactly 1, 4 or 8 bytes, big-endian.
#[test]
fn s017_t03_r03_integer_widths() {
    for fields in [
        &[(0, &[][..])][..],
        &[(0, &[1, 2])],
        &[(0, &[1]), (1, &[0; 3])],
        &[(0, &[1]), (1, &[0; 5])],
        &[(0, &[1]), (2, &[0; 7])],
        &[(0, &[1]), (2, &[0; 9])],
    ] {
        assert_eq!(error(&record(fields), Reject), Some(Width), "{fields:?}");
    }
    let maxima = record(&[(0, &[0xff]), (1, &[0xff; 4]), (2, &[0xff; 8])]);
    let decoded = TestRecord::decode(&maxima, Reject).unwrap();
    assert_eq!(decoded.small, u8::MAX);
    assert_eq!(decoded.medium, Some(u32::MAX));
    assert_eq!(decoded.large, Some(u64::MAX));
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
    for (fields, expected) in [
        (&[(0, &[1][..]), (4, &[0; 31])][..], Width),
        (&[(0, &[1]), (4, &[0; 33])], Width),
        (&[(0, &[1]), (3, &too_long)], TooLong),
        (&[(0, &[1]), (5, &too_long)], TooLong),
        (&[(0, &[1]), (5, &[b'a', 0xff])], Utf8),
    ] {
        assert_eq!(error(&record(fields), Reject), Some(expected), "{fields:?}");
    }
}

/// Spec 017, R5: `end` frames whatever is left and applies the policy to it.
#[test]
fn s017_t05_r05_end_walks_the_rest() {
    let valid = record(&[(0, &[1]), (5, b"hi")]);
    let extra_byte = [&valid[..], &[0]].concat();
    let extra_field = [valid, field(9, b"x")].concat();
    for policy in POLICIES {
        assert_eq!(error(&extra_byte, policy), Some(Truncated));
    }
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
}

/// Spec 017, R8: the whole-record limit is checked before any field, so even
/// bytes that would not frame return `TooLong`.
#[test]
fn s017_t08_r08_whole_record_limit() {
    let head = record(&[(0, &[1]), (3, &[b'a'; MAX_BYTES])]);
    let filler = vec![0; MAX_RECORD - head.len() - 5];
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
        (5, "é".as_bytes()),
    ]);
    let decoded = TestRecord::decode(&buf, Reject).unwrap();
    let expected = TestRecord {
        small: 1,
        medium: Some(2),
        large: Some(3),
        bytes: Some(&nested),
        bytes32: Some(&[4; 32]),
        text: Some("é"),
    };
    assert_eq!(decoded, expected);
}

proptest! {
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
