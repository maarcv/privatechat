//! Tests of spec 020 over the log record.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, proptest};
use zeroize::Zeroizing;

use super::super::tests::{field, key};
use super::super::{DirName, MAX_NAME, StoreError};
use super::{Content, LogEntry, LogRecord, MAX_LOG_RECORD, Message};
use crate::crypto::{PublicKey, Signature};
use crate::proto::payload::MAX_PAYLOAD;
use crate::vectors::{Kind, Value, Vector};

/// A received text message of `body_len` bytes, as spec 021 would write it.
fn message(body_len: usize) -> LogRecord {
    LogRecord {
        purge_at: 1,
        entry: LogEntry::Message(Message {
            server_id: Some([2; 16]),
            received_at: 3,
            sender_pk: PublicKey([4; 32]),
            counter: 5,
            content: Content::Text(Zeroizing::new(vec![b'b'; body_len])),
            display_name: Some(Zeroizing::new(b"Anna".to_vec())),
            sent_at: Some(6),
            own_client_ref: None,
        }),
    }
}

/// One record of each kind, and a message of each content.
fn every_kind() -> Vec<LogRecord> {
    let other = |content, own| LogRecord {
        purge_at: 7,
        entry: LogEntry::Message(Message {
            server_id: None,
            received_at: 8,
            sender_pk: PublicKey([9; 32]),
            counter: 10,
            content,
            display_name: None,
            sent_at: None,
            own_client_ref: own,
        }),
    };
    let record = |entry| LogRecord {
        purge_at: 11,
        entry,
    };
    vec![
        message(20),
        other(Content::KeyRetired, Some([12; 16])),
        other(Content::Unreadable, None),
        record(LogEntry::Acked {
            server_id: [13; 16],
            received_at: 14,
            client_ref: [15; 16],
        }),
        record(LogEntry::NotDelivered {
            client_ref: [16; 16],
        }),
        record(LogEntry::KeptSignature {
            sent_at: 17,
            client_ref: [18; 16],
            signature: Signature([19; 64]),
            epoch: 20,
        }),
        record(LogEntry::Seen {
            server_id: [21; 16],
            sender_pk: PublicKey([22; 32]),
            counter: 23,
        }),
    ]
}

/// The record's encoding at generation 1, offset 9.
fn encode(record: &LogRecord) -> Zeroizing<Vec<u8>> {
    record.encode(1, 9).unwrap()
}

/// Spec 020, R8 (the log record): key 0 fixes the keys a record has, so an
/// unknown kind, a key of another kind, a text without its body, a body on a
/// `key_retired`, or an own message without its `client_ref` is `Corrupt`.
#[test]
fn s020_t08_r08_log_schema() {
    let decode = |buf: &[u8]| LogRecord::decode(buf).err();
    for record in every_kind() {
        let buf = encode(&record);
        assert_eq!(decode(&buf), None);
        assert_eq!(
            decode(&[&buf[..], &field(16, &[])].concat()),
            Some(StoreError::Corrupt)
        );
    }
    // Key 0 is the first field; its value sits at byte 5.
    let mut unknown_kind = encode(&message(3)).to_vec();
    unknown_kind[5] = 5;
    assert_eq!(decode(&unknown_kind), Some(StoreError::Corrupt));
    // A `not delivered` with a key 14 that only a kept signature has.
    let not_delivered = encode(&every_kind().remove(4));
    let with_signature = [&not_delivered[..], &field(14, &[0; 64])].concat();
    assert_eq!(decode(&with_signature), Some(StoreError::Corrupt));
    // The head of every record, then a message's own keys cut or doubled.
    let head = [
        field(0, &[0]),
        field(1, &[0; 4]),
        field(2, &[0; 8]),
        field(3, &[0; 8]),
    ]
    .concat();
    let message_keys = |content: u8, body: bool, own: u8, client_ref: bool| {
        let mut buf = head.clone();
        buf.extend(field(5, &[0; 8]));
        buf.extend(field(6, &[0; 32]));
        buf.extend(field(7, &[0; 8]));
        buf.extend(field(8, &[content]));
        if body {
            buf.extend(field(11, b"hi"));
        }
        buf.extend(field(12, &[own]));
        if client_ref {
            buf.extend(field(13, &[0; 16]));
        }
        buf
    };
    assert_eq!(decode(&message_keys(0, true, 0, false)), None);
    assert_eq!(decode(&message_keys(1, false, 1, true)), None);
    for (content, body, own, client_ref) in [
        (0, false, 0, false),
        (1, true, 0, false),
        (2, true, 0, false),
        (3, false, 0, false),
        (0, true, 1, false),
        (0, true, 0, true),
        (0, true, 2, false),
    ] {
        let buf = message_keys(content, body, own, client_ref);
        assert_eq!(
            decode(&buf),
            Some(StoreError::Corrupt),
            "{content} {body} {own} {client_ref}"
        );
    }
}

/// Spec 020, R9: a record carries its generation and offset, and opens only
/// where it was sealed, in the directory it was sealed for.
#[test]
fn s020_t09_r09_entry_bound_to_place() {
    let storage_key = key(1);
    let (a, b) = (DirName([2; 16]), DirName([3; 16]));
    let record = message(10);
    let sealed = record.seal(&storage_key, &a, 4, 100).unwrap();
    let opened = LogRecord::open(&storage_key, &a, &sealed, 4, 100).unwrap();
    assert_eq!(encode(&opened), encode(&record));
    for (name, generation, offset) in [(&a, 4, 101), (&a, 5, 100), (&a, 3, 100), (&b, 4, 100)] {
        let error = LogRecord::open(&storage_key, name, &sealed, generation, offset).err();
        assert_eq!(error, Some(StoreError::Corrupt), "{generation} {offset}");
    }
    let (_, generation, offset) = LogRecord::decode(&record.encode(4, 100).unwrap()).unwrap();
    assert_eq!((generation, offset), (4, 100));
}

/// Spec 020, R25 and R27 (the log record): the buffer is allocated at the
/// encoded length, the longest body and name fit within the record limit,
/// and one byte more of either is refused on seal as on open.
#[test]
fn s020_t27_r27_log_within_limits() {
    for record in every_kind() {
        let buf = encode(&record);
        assert_eq!(buf.capacity(), buf.len());
    }
    let mut longest = message(MAX_PAYLOAD);
    if let LogEntry::Message(message) = &mut longest.entry {
        message.display_name = Some(Zeroizing::new(vec![b'n'; MAX_NAME]));
    }
    let buf = longest.encode(u32::MAX, u64::MAX).unwrap();
    assert!(buf.len() <= MAX_LOG_RECORD, "{}", buf.len());
    assert!(LogRecord::decode(&buf).is_ok());
    assert_eq!(
        message(MAX_PAYLOAD + 1).encode(1, 9).err(),
        Some(StoreError::Corrupt)
    );
    let mut long_name = message(3);
    if let LogEntry::Message(message) = &mut long_name.entry {
        message.display_name = Some(Zeroizing::new(vec![b'n'; MAX_NAME + 1]));
    }
    assert_eq!(long_name.encode(1, 9).err(), Some(StoreError::Corrupt));
}

/// The value of `field` in a vector's expected values, if it has one.
fn optional<'a>(vector: &'a Vector, field: &str) -> Option<&'a Value> {
    vector.has_expected(field).then(|| vector.expected(field))
}

/// Checks a log vector of `020.json`: a positive decodes to every value it
/// names and encodes back to its bytes; a negative is `Corrupt`.
pub(in crate::storage) fn check_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "log");
    let buf = vector.input("record").bytes();
    let decoded = LogRecord::decode(buf);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.err().unwrap());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        return;
    }
    let (record, generation, offset) = decoded.unwrap();
    let expected = |field| vector.expected(field);
    assert_eq!(generation, expected("generation").number());
    assert_eq!(offset, expected("offset").u64_hex());
    assert_eq!(record.purge_at(), expected("purge_at").u64_hex());
    let kind = expected("kind").number();
    match &record.entry {
        LogEntry::Message(message) => {
            assert_eq!(kind, 0);
            let server_id = message.server_id.map(|id| id.to_vec());
            assert_eq!(
                server_id.as_deref(),
                optional(vector, "server_id").map(Value::bytes)
            );
            assert_eq!(message.received_at, expected("received_at").u64_hex());
            assert_eq!(message.sender_pk.0, expected("sender_pk").array::<32>());
            assert_eq!(message.counter, expected("counter").u64_hex());
            let (content, body) = match &message.content {
                Content::Text(body) => (0, Some(body.as_slice())),
                Content::KeyRetired => (1, None),
                Content::Unreadable => (2, None),
            };
            assert_eq!(content, expected("content").number());
            assert_eq!(body, optional(vector, "body").map(Value::bytes));
            let name = message.display_name.as_ref().map(|name| name.as_slice());
            assert_eq!(name, optional(vector, "display_name").map(Value::bytes));
            assert_eq!(
                message.sent_at,
                optional(vector, "sent_at").map(Value::u64_hex)
            );
            assert_eq!(message.own_client_ref.is_some(), expected("own").flag());
            let client_ref = message.own_client_ref.map(|id| id.to_vec());
            assert_eq!(
                client_ref.as_deref(),
                optional(vector, "client_ref").map(Value::bytes)
            );
        }
        LogEntry::KeptSignature {
            sent_at,
            client_ref,
            signature,
            epoch,
        } => {
            assert_eq!(kind, 3);
            assert_eq!(*sent_at, expected("sent_at").u64_hex());
            assert_eq!(*client_ref, expected("client_ref").array::<16>());
            assert_eq!(signature.0, expected("signature").array::<64>());
            assert_eq!(*epoch, expected("epoch").number());
        }
        LogEntry::Seen {
            server_id,
            sender_pk,
            counter,
        } => {
            assert_eq!(kind, 4);
            assert_eq!(*server_id, expected("server_id").array::<16>());
            assert_eq!(sender_pk.0, expected("sender_pk").array::<32>());
            assert_eq!(*counter, expected("counter").u64_hex());
        }
        // No vector has these kinds; the bytes below still compare.
        LogEntry::Acked { .. } => assert_eq!(kind, 1),
        LogEntry::NotDelivered { .. } => assert_eq!(kind, 2),
    }
    assert_eq!(record.encode(generation, offset).unwrap().as_slice(), buf);
}

proptest! {
    /// Spec 020, R29 (the log record): a record of each kind re-encodes to
    /// the bytes it was decoded from, at any generation and offset.
    #[test]
    fn s020_t29_r29_log_round_trip(
        generation in any::<u32>(),
        offset in any::<u64>(),
        numbers in any::<(u64, u64, u64)>(),
        body in bytes_of(any::<u8>(), 0..=2_000),
        display_name in maybe(bytes_of(any::<u8>(), 0..=MAX_NAME)),
        ids in any::<(Option<[u8; 16]>, Option<[u8; 16]>, Option<u64>)>(),
    ) {
        let (purge_at, received_at, counter) = numbers;
        let (server_id, own, sent_at) = ids;
        let mut records = every_kind();
        records.push(LogRecord {
            purge_at,
            entry: LogEntry::Message(Message {
                server_id,
                received_at,
                sender_pk: PublicKey([1; 32]),
                counter,
                content: Content::Text(Zeroizing::new(body)),
                display_name: display_name.map(Zeroizing::new),
                sent_at,
                own_client_ref: own,
            }),
        });
        for record in records {
            let buf = record.encode(generation, offset).unwrap();
            let (decoded, read_generation, read_offset) = LogRecord::decode(&buf).unwrap();
            assert_eq!((read_generation, read_offset), (generation, offset));
            assert_eq!(decoded.encode(generation, offset).unwrap(), buf);
        }
    }

    /// Spec 020, R29 (the log record): the decoder never panics on arbitrary
    /// bytes, nor on a valid record with one byte changed.
    #[test]
    fn s020_t29_r29_log_never_panics(
        buf in bytes_of(any::<u8>(), 0..=512),
        flip in any::<(usize, usize, u8)>(),
    ) {
        let _ = LogRecord::decode(&buf);
        let records = every_kind();
        let mut changed = encode(&records[flip.0 % records.len()]).to_vec();
        let at = flip.1 % changed.len();
        changed[at] ^= flip.2;
        let _ = LogRecord::decode(&changed);
    }
}
