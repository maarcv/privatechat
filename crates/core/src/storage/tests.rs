//! Tests of spec 020 over the records `core` seals and opens.

use super::state::ChannelState;
use super::state::tests::{encode, small_state};
use super::{
    DirName, MIN_SEALED, StorageKey, StoreError, dir_name, open_box, seal_box, settings_key,
    store_key,
};
use crate::crypto::Secret;
use crate::proto::record::UnknownKeys::Reject;
use crate::proto::record::test_schema::TypesRecord;
use crate::vectors::{self, Checker, Kind, Vector};

/// One field: key ‖ 4-byte big-endian length ‖ value (spec 017 R1).
pub(super) fn field(key: u8, value: &[u8]) -> Vec<u8> {
    let len = u32::try_from(value.len()).unwrap();
    [&[key][..], &len.to_be_bytes(), value].concat()
}

/// Spec 020, R26: each variant is a unit variant whose `Debug` is its name,
/// and `core::Error` carries it as it is.
#[test]
fn s020_t26_r26_store_error_has_no_data() {
    for (error, name) in [
        (StoreError::Io, "Io"),
        (StoreError::Locked, "Locked"),
        (StoreError::Corrupt, "Corrupt"),
        (StoreError::UnsupportedVersion, "UnsupportedVersion"),
        (StoreError::LogFull, "LogFull"),
        (StoreError::OutboxFull, "OutboxFull"),
    ] {
        let exhaustive = match error {
            StoreError::Io
            | StoreError::Locked
            | StoreError::Corrupt
            | StoreError::UnsupportedVersion
            | StoreError::LogFull
            | StoreError::OutboxFull => format!("{error:?}"),
        };
        assert_eq!(exhaustive, name);
        assert_eq!(crate::Error::from(error), crate::Error::Store(error));
    }
}

/// The fields of a well-framed record, in order.
pub(super) fn fields(buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut rest = buf;
    let mut found = Vec::new();
    while let Some((&key, after)) = rest.split_first() {
        let len = usize::try_from(u32::from_be_bytes(after[..4].try_into().unwrap())).unwrap();
        found.push((key, after[4..4 + len].to_vec()));
        rest = &after[4 + len..];
    }
    found
}

/// `buf` without the field of `key`.
pub(super) fn without(buf: &[u8], key: u8) -> Vec<u8> {
    let kept = fields(buf).into_iter().filter(|(at, _)| *at != key);
    kept.flat_map(|(at, value)| field(at, &value)).collect()
}

/// `buf` with the value of `key` replaced, or the field inserted in key
/// order when absent.
pub(super) fn replaced(buf: &[u8], key: u8, value: &[u8]) -> Vec<u8> {
    let mut all = fields(buf);
    all.retain(|(at, _)| *at != key);
    all.push((key, value.to_vec()));
    all.sort_by_key(|(at, _)| *at);
    all.into_iter()
        .flat_map(|(at, value)| field(at, &value))
        .collect()
}

/// A list value of these items, each `len` ‖ item (R1).
pub(super) fn list_value(items: &[Vec<u8>]) -> Vec<u8> {
    let framed =
        |item: &Vec<u8>| [&u32::try_from(item.len()).unwrap().to_be_bytes()[..], item].concat();
    items.iter().flat_map(framed).collect()
}

/// Spec 020, Limits: the numbers `store` checks before it reads a file, and
/// the record maxima they come from, as the table writes them.
#[test]
fn s020_t06_r06_file_limits_are_the_table() {
    assert_eq!(super::MAX_STATE_FILE, 2_359_341);
    assert_eq!(super::MAX_SETTINGS_FILE, 1_069);
    assert_eq!(super::MAX_LOG_ENTRY, 65_576);
    assert_eq!(super::MAX_LOG_LEN, 67_108_864);
    assert_eq!(super::state::MAX_STATE_RECORD, 2_359_296);
    assert_eq!(super::log::MAX_LOG_RECORD, 65_536);
    assert_eq!(super::settings::MAX_SETTINGS_RECORD, 1_024);
}

/// A storage key of `byte`, repeated.
pub(super) fn key(byte: u8) -> StorageKey {
    StorageKey::from_bytes(&mut [byte; 32])
}

/// Spec 020, R3: each directory's state is sealed under its own key, and
/// neither opens under another directory's name nor as settings.
#[test]
fn s020_t03_r03_derived_keys() {
    let storage_key = key(1);
    let (a, b) = (DirName([2; 16]), DirName([3; 16]));
    let state = small_state();
    let sealed = state.seal(&storage_key, &a, 9, 0).unwrap();
    assert!(ChannelState::open(&storage_key, &a, &sealed).is_ok());
    assert_eq!(
        ChannelState::open(&storage_key, &b, &sealed).err(),
        Some(StoreError::Corrupt)
    );
    let as_settings = open_box(&settings_key(&storage_key).unwrap(), &sealed);
    assert_eq!(as_settings.err(), Some(StoreError::Corrupt));
    // No file key is `K_db` itself, and the two derived keys differ.
    let own = store_key(&storage_key, &a).unwrap();
    assert_ne!(own.expose(), &[1; 32]);
    assert_ne!(own.expose(), settings_key(&storage_key).unwrap().expose());
    assert!(open_box(&Secret::from_bytes([1; 32]), &sealed).is_err());
    let settings_key = settings_key(&storage_key).unwrap();
    assert_ne!(settings_key.expose(), &[1; 32]);
    let settings = crate::testing::settings("wss://chat.example.org", 0, None);
    let under_k_db = seal_box(&Secret::from_bytes([1; 32]), &settings.encode().unwrap()).unwrap();
    let opened = super::Settings::open(&storage_key, &under_k_db);
    assert_eq!(opened.err(), Some(StoreError::Corrupt));
}

/// Spec 020, R3 and R18: the tags and the 16-byte cut of the derivations,
/// against values computed with Python's `hashlib.blake2b` keyed by
/// `K_db = [1; 32]`, so that a changed tag, which would orphan every file on
/// disk, fails here.
#[test]
fn s020_t03_r03_derivations_known_answer() {
    let storage_key = key(1);
    let name = dir_name(&storage_key, &[9; 16]).unwrap();
    assert_eq!(hex(&name.0), "51c69090ec167c99665175b0716aad01");
    let store = store_key(&storage_key, &name).unwrap();
    let expected = "5fc5de47d99bd818b955136d20a711a1711a42e51d0a01be1eeebc816fd8629a";
    assert_eq!(hex(store.expose()), expected);
    let settings = settings_key(&storage_key).unwrap();
    let expected = "1fd2b36decb84451baafabf4b368cd521d796e490ad06237b2196265239913cd";
    assert_eq!(hex(settings.expose()), expected);
}

/// Lowercase hex, for the known answers.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Spec 020, R4 (`core`'s half): two seals of one state differ in their
/// fresh 24-byte nonce and open to the same record.
#[test]
fn s020_t04_r04_seals_differ_in_their_nonce() {
    let storage_key = key(1);
    let name = DirName([2; 16]);
    let state = small_state();
    let first = state.seal(&storage_key, &name, 9, 0).unwrap();
    let second = state.seal(&storage_key, &name, 9, 0).unwrap();
    assert_eq!(first.len(), second.len());
    assert_ne!(first[..24], second[..24]);
    let record = encode(&state).unwrap();
    for sealed in [first, second] {
        assert_eq!(sealed.len(), 24 + 16 + record.len());
        let opened = ChannelState::open(&storage_key, &name, &sealed).unwrap();
        assert_eq!(encode(&opened).unwrap(), record);
    }
}

/// Spec 020, R7 (`core`'s half): 39 bytes, a flipped byte anywhere in the
/// box and a box that holds a broken record are all `Corrupt`.
#[test]
fn s020_t07_r07_open_check_order() {
    let storage_key = key(1);
    let name = DirName([2; 16]);
    assert_eq!(MIN_SEALED, 40);
    let open = |sealed: &[u8]| ChannelState::open(&storage_key, &name, sealed).err();
    assert_eq!(open(&[0; 39]), Some(StoreError::Corrupt));
    assert_eq!(open(&[0; 40]), Some(StoreError::Corrupt));
    let sealed = small_state().seal(&storage_key, &name, 9, 0).unwrap();
    for at in [0, 23, 24, 39, sealed.len() - 1] {
        let mut flipped = sealed.clone();
        flipped[at] ^= 1;
        assert_eq!(open(&flipped), Some(StoreError::Corrupt), "byte {at}");
    }
    let file_key = store_key(&storage_key, &name).unwrap();
    let broken = seal_box(&file_key, &[0, 0, 0, 0, 1]).unwrap();
    assert_eq!(open(&broken), Some(StoreError::Corrupt));
    let empty = seal_box(&file_key, &[]).unwrap();
    assert_eq!(empty.len(), MIN_SEALED);
    assert_eq!(open(&empty), Some(StoreError::Corrupt));
}

/// Spec 020, R18 (`core`'s half): the name is 16 bytes of a keyed hash, so it
/// differs under two keys and does not hold the `channel_id`.
#[test]
fn s020_t18_r18_directory_name_is_keyed() {
    let channel_id = [9; 16];
    let first = dir_name(&key(1), &channel_id).unwrap();
    assert_eq!(first, dir_name(&key(1), &channel_id).unwrap());
    assert_ne!(first, dir_name(&key(2), &channel_id).unwrap());
    assert_ne!(first, dir_name(&key(1), &[8; 16]).unwrap());
    assert_ne!(first.0, channel_id);
    assert!(!first.0.windows(4).any(|window| window == [9; 4]));
}

/// Spec 020, R24: the input array is zeros once the key has taken it.
#[test]
fn s020_t24_r24_storage_key_zeroes_input() {
    let mut bytes = [7u8; 32];
    let storage_key = StorageKey::from_bytes(&mut bytes);
    assert_eq!(bytes, [0; 32]);
    // The key still works: it was copied before the input was wiped.
    let name = DirName([2; 16]);
    let sealed = small_state().seal(&storage_key, &name, 9, 0).unwrap();
    let under_sevens = ChannelState::open(&key(7), &name, &sealed);
    assert!(under_sevens.is_ok());
}

/// Spec 020, R28 (`core`'s half): a store, a vault and what a commit takes
/// can move to another thread, so `Device` can live behind a `Mutex`.
#[test]
fn s020_t28_r28_send() {
    fn is_send<T: Send + ?Sized>() {}
    is_send::<Box<dyn super::Store>>();
    is_send::<Box<dyn super::Vault>>();
    is_send::<super::WriteBatch>();
    is_send::<super::StorageKey>();
}

/// Checks a codec vector of `020.json`: a positive decodes to its values and
/// encodes back to its bytes, a negative returns its `RecordError`.
fn check_types_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "types");
    assert_eq!(vector.input("policy").text(), "reject");
    let record = vector.input("record").bytes();
    let decoded = TypesRecord::decode(record, Reject);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.unwrap_err());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        // Each negative is key 0 and the one field that breaks its rule.
        let numbers: Vec<Vec<u8>> = (0u64..5).map(|n| n.to_be_bytes().to_vec()).collect();
        let broken = match vector.name() {
            "bool_two" => field(1, &[2]),
            "list_item_truncated" => field(3, &[0, 0, 0, 8, 0, 0, 0]),
            _ => field(3, &list_value(&numbers)),
        };
        assert_eq!(
            record,
            [field(0, &[1]), broken].concat(),
            "{}",
            vector.name()
        );
        return;
    }
    let decoded = decoded.unwrap();
    let optional = |field| vector.has_expected(field).then(|| vector.expected(field));
    let small = u8::try_from(vector.expected("small").number()).unwrap();
    assert_eq!(decoded.small, small, "{}", vector.name());
    assert_eq!(decoded.flag, optional("flag").map(|value| value.flag()));
    let nested = decoded
        .nested
        .as_ref()
        .map(|nested| nested.encode().unwrap().to_vec());
    assert_eq!(
        nested.as_deref(),
        optional("nested").map(|value| value.bytes())
    );
    let numbers =
        optional("numbers").map(|value| value.list().iter().map(|n| n.u64_hex()).collect());
    assert_eq!(decoded.numbers, numbers, "{}", vector.name());
    assert_eq!(
        decoded.encode().unwrap().as_slice(),
        record,
        "{}",
        vector.name()
    );
}

/// Spec 015, R3: every vector of `020.json` is checked once.
#[test]
fn s020_vectors_dispatch() {
    let types: [&str; 8] = [
        "bool_true",
        "bool_false",
        "bool_two",
        "nested_record",
        "list_two_items",
        "list_empty",
        "list_item_truncated",
        "list_too_many",
    ];
    let mut entries: Vec<(&str, Checker)> = types
        .iter()
        .map(|name| (*name, check_types_vector as Checker))
        .collect();
    for name in ["state_reference", "state_unknown_key"] {
        entries.push((name, super::state::tests::check_state_vector));
    }
    for name in [
        "log_message_reference",
        "log_kept_signature_reference",
        "log_seen_reference",
        "log_unknown_key",
    ] {
        entries.push((name, super::log::tests::check_vector));
    }
    for name in ["settings_reference", "settings_bad_url"] {
        entries.push((name, super::settings::tests::check_vector));
    }
    vectors::check_all("020", &entries);
}
