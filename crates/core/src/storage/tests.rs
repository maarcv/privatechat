//! Tests of spec 020 over the records `core` seals and opens.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, prop, proptest};

use super::state::items::{
    MAX_BLOB, MAX_OLD_KEY, MAX_OUTBOX_ENTRY, MAX_PEER_RECORD, OldKey, OutboxEntry, OutboxKind,
    PeerRecord,
};
use super::state::{ChannelState, MAX_OLD_KEYS, MAX_OUTBOX, MAX_PEERS, MAX_STATE_RECORD};
use super::{
    DirName, MAX_NAME, MIN_SEALED, StorageKey, StoreError, dir_name, open_box, seal_box,
    settings_key, store_key,
};
use crate::crypto::{PublicKey, Secret, Signature};
use crate::proto::config;
use crate::proto::record::ITEM_HEADER_LEN;
use crate::proto::record::UnknownKeys::Reject;
use crate::proto::record::test_schema::TypesRecord;
use crate::vectors::{self, Checker, Kind, Vector};

/// One field: key ‖ 4-byte big-endian length ‖ value (spec 017 R1).
pub(super) fn field(key: u8, value: &[u8]) -> Vec<u8> {
    let len = u32::try_from(value.len()).unwrap();
    [&[key][..], &len.to_be_bytes(), value].concat()
}

/// A peer with every field present, names at `name_len` bytes.
fn full_peer(name_len: usize) -> PeerRecord {
    PeerRecord {
        pk: PublicKey([1; 32]),
        label: Some("l".repeat(name_len)),
        verified: true,
        muted: false,
        retired_at: Some(2),
        first_seen: 3,
        last_seen: 4,
        max_counter: Some(5),
        last_display_name: Some(vec![b'n'; name_len]),
    }
}

/// An `outbox` entry whose blob has `blob_len` bytes.
fn entry(blob_len: usize) -> OutboxEntry {
    OutboxEntry {
        client_ref: [6; 16],
        kind: OutboxKind::KeyRetired,
        sent_at: 7,
        blob: vec![8; blob_len],
        signature: Signature([9; 64]),
        under_retired_key: true,
        counter: 10,
    }
}

/// Spec 020, R27 (the items of the three lists): the bounds of the Limits
/// table, which seal refuses as open does.
#[test]
fn s020_t27_r27_list_items_within_limits() {
    assert_eq!(MAX_NAME, 64);
    assert_eq!(MAX_BLOB, 64_673);
    assert_eq!(MAX_PEER_RECORD + ITEM_HEADER_LEN, 243);
    assert_eq!(MAX_OUTBOX_ENTRY + ITEM_HEADER_LEN, 64_810);
    assert_eq!(MAX_OLD_KEY + ITEM_HEADER_LEN, 54);
    let largest = full_peer(MAX_NAME).encode().unwrap();
    assert_eq!(largest.len(), MAX_PEER_RECORD);
    assert_eq!(entry(MAX_BLOB).encode().unwrap().len(), MAX_OUTBOX_ENTRY);
    let long_label = PeerRecord {
        last_display_name: None,
        ..full_peer(MAX_NAME + 1)
    };
    let long_name = PeerRecord {
        label: None,
        ..full_peer(MAX_NAME + 1)
    };
    for peer in [long_label, long_name] {
        assert_eq!(peer.encode().err(), Some(StoreError::Corrupt));
    }
    assert_eq!(
        entry(MAX_BLOB + 1).encode().err(),
        Some(StoreError::Corrupt)
    );
    // The same bounds on open: a 65-byte label, a 65-byte name, a long blob.
    let peer = |key: u8, value: &[u8]| {
        let mut buf = field(0, &[1; 32]);
        if key == 1 {
            buf.extend(field(1, value));
        }
        buf.extend([field(2, &[0]), field(3, &[0])].concat());
        buf.extend([field(5, &[0; 8]), field(6, &[0; 8])].concat());
        if key == 8 {
            buf.extend(field(8, value));
        }
        buf
    };
    let over = [b'a'; MAX_NAME + 1];
    for key in [1, 8] {
        assert!(PeerRecord::decode(&peer(key, &over[..MAX_NAME])).is_ok());
        let error = PeerRecord::decode(&peer(key, &over)).err();
        assert_eq!(error, Some(StoreError::Corrupt), "key {key}");
    }
    let mut long_blob = entry(MAX_BLOB).encode().unwrap().to_vec();
    long_blob.splice(24..24, [0]);
    long_blob[20..24].copy_from_slice(&u32::try_from(MAX_BLOB + 1).unwrap().to_be_bytes());
    let error = OutboxEntry::decode(&long_blob).err();
    assert_eq!(error, Some(StoreError::Corrupt));
}

/// Spec 020, R8 (the items of the three lists): each decodes under `Reject`
/// with its mandatory keys, and an `outbox` kind other than 0 and 1 is
/// `Corrupt`.
#[test]
fn s020_t08_r08_list_item_schemas() {
    let unknown = |mut buf: Vec<u8>| {
        buf.extend(field(20, &[]));
        buf
    };
    let peer = full_peer(3).encode().unwrap().to_vec();
    let outbox = entry(100).encode().unwrap().to_vec();
    let old_key = OldKey {
        pk: PublicKey([2; 32]),
        retired_at: 3,
    };
    let old_key = old_key.encode().unwrap().to_vec();
    type Decode = fn(&[u8]) -> Option<StoreError>;
    let decoders: [(&Vec<u8>, Decode); 3] = [
        (&peer, |buf| PeerRecord::decode(buf).err()),
        (&outbox, |buf| OutboxEntry::decode(buf).err()),
        (&old_key, |buf| OldKey::decode(buf).err()),
    ];
    for (buf, decode) in decoders {
        assert_eq!(decode(buf), None);
        assert_eq!(decode(&unknown(buf.clone())), Some(StoreError::Corrupt));
        // Without key 0, which every item has as its first field.
        let first_len = 5 + usize::from(buf[4]);
        assert_eq!(decode(&buf[first_len..]), Some(StoreError::Corrupt));
    }
    // Key 1 of an `outbox` entry sits at byte 21, its value at byte 26.
    for (kind, expected) in [
        (0, Some(OutboxKind::Text)),
        (1, Some(OutboxKind::KeyRetired)),
        (2, None),
    ] {
        let mut buf = outbox.clone();
        buf[26] = kind;
        assert_eq!(
            OutboxEntry::decode(&buf).ok().map(|entry| entry.kind),
            expected
        );
    }
}

/// A state with every optional field absent and every list empty.
fn small_state() -> ChannelState {
    ChannelState {
        channel_id: [1; 16],
        config: zeroize::Zeroizing::new(vec![2; 40]),
        identity_seed: Secret::from_bytes([3; 32]),
        identity_epoch: 0,
        send_counter: 0,
        cursor: None,
        own_display_name: None,
        local_name: None,
        peers: Vec::new(),
        outbox: Vec::new(),
        retiring_seed: None,
        own_old_keys: Vec::new(),
        own_key_used_elsewhere: false,
        read_only: false,
        log_committed_len: 9,
        log_generation: 0,
        synced_at: None,
        truncated_at: None,
    }
}

/// The largest state the Limits table allows.
fn largest_state() -> ChannelState {
    let old_key = OldKey {
        pk: PublicKey([4; 32]),
        retired_at: 5,
    };
    ChannelState {
        config: zeroize::Zeroizing::new(vec![2; config::MAX_RECORD]),
        cursor: Some(6),
        own_display_name: Some("o".repeat(MAX_NAME)),
        local_name: Some("l".repeat(MAX_NAME)),
        peers: vec![full_peer(MAX_NAME); MAX_PEERS],
        outbox: vec![entry(MAX_BLOB); MAX_OUTBOX],
        retiring_seed: Some(Secret::from_bytes([7; 32])),
        own_old_keys: vec![old_key; MAX_OLD_KEYS],
        synced_at: Some(8),
        truncated_at: Some(9),
        ..small_state()
    }
}

/// `state` encoded at the log position it holds.
fn encode(state: &ChannelState) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
    let (log_len, generation) = state.log_position();
    state.encode(log_len, generation)
}

/// Spec 020, R8 (the state record): key 0 is read first, so a newer version
/// is `UnsupportedVersion` even with a key this version does not know; the
/// rest decodes under `Reject`.
#[test]
fn s020_t08_r08_state_schema() {
    let record = encode(&small_state()).unwrap().to_vec();
    assert_eq!(&record[..6], [0, 0, 0, 0, 1, 1]);
    let with_unknown = [&record[..], &field(19, &[])].concat();
    assert_eq!(
        ChannelState::decode(&with_unknown).err(),
        Some(StoreError::Corrupt)
    );
    let mut newer = with_unknown.clone();
    newer[5] = 2;
    assert_eq!(
        ChannelState::decode(&newer).err(),
        Some(StoreError::UnsupportedVersion)
    );
    // Without key 0, and with a mandatory key missing.
    assert_eq!(
        ChannelState::decode(&record[6..]).err(),
        Some(StoreError::Corrupt)
    );
    assert_eq!(
        ChannelState::decode(&record[..27]).err(),
        Some(StoreError::Corrupt)
    );
    assert_eq!(ChannelState::decode(&[]).err(), Some(StoreError::Corrupt));
}

/// Spec 020, R25 (the state record): the writer's buffer is allocated at the
/// encoded length, for a small state and for the largest.
#[test]
fn s020_t25_r25_state_buffer_is_exact() {
    for state in [small_state(), largest_state()] {
        let record = encode(&state).unwrap();
        assert_eq!(record.capacity(), record.len());
    }
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

/// Spec 020, R27 (the state record): 33 `outbox` entries are `OutboxFull`,
/// one peer or old key over the limit or a long name is `Corrupt`, and the
/// largest state encodes within the record limit and decodes back.
#[test]
fn s020_t27_r27_state_within_limits() {
    let over_outbox = ChannelState {
        outbox: vec![entry(10); MAX_OUTBOX + 1],
        ..small_state()
    };
    assert_eq!(encode(&over_outbox).err(), Some(StoreError::OutboxFull));
    let over_peers = ChannelState {
        peers: vec![full_peer(1); MAX_PEERS + 1],
        ..small_state()
    };
    let old_key = OldKey {
        pk: PublicKey([4; 32]),
        retired_at: 5,
    };
    let over_old_keys = ChannelState {
        own_old_keys: vec![old_key; MAX_OLD_KEYS + 1],
        ..small_state()
    };
    let long_name = ChannelState {
        local_name: Some("l".repeat(MAX_NAME + 1)),
        ..small_state()
    };
    let long_config = ChannelState {
        config: zeroize::Zeroizing::new(vec![2; config::MAX_RECORD + 1]),
        ..small_state()
    };
    let long_label = ChannelState {
        peers: vec![full_peer(MAX_NAME + 1)],
        ..small_state()
    };
    for state in [
        over_peers,
        over_old_keys,
        long_name,
        long_config,
        long_label,
    ] {
        assert_eq!(encode(&state).err(), Some(StoreError::Corrupt));
    }
    let largest = encode(&largest_state()).unwrap();
    assert!(largest.len() <= MAX_STATE_RECORD, "{}", largest.len());
    let decoded = ChannelState::decode(&largest).unwrap();
    assert_eq!(encode(&decoded).unwrap(), largest);
    // One peer over the limit, planted in the bytes, does not open either.
    let full = ChannelState {
        peers: vec![full_peer(1); MAX_PEERS],
        ..small_state()
    };
    let mut buf = encode(&full).unwrap().to_vec();
    assert!(ChannelState::decode(&buf).is_ok());
    // Keys 0 to 5 of `small_state` take 131 bytes; key 9 follows.
    let peers_at = 131;
    assert_eq!(buf[peers_at], 9);
    let len_range = peers_at + 1..peers_at + 5;
    let len = u32::from_be_bytes(buf[len_range.clone()].try_into().unwrap());
    let item = full_peer(1).encode().unwrap();
    let extra = [&u32::try_from(item.len()).unwrap().to_be_bytes()[..], &item].concat();
    let end = peers_at + 5 + usize::try_from(len).unwrap();
    buf.splice(end..end, extra.iter().copied());
    let new_len = len + u32::try_from(extra.len()).unwrap();
    buf[len_range].copy_from_slice(&new_len.to_be_bytes());
    assert_eq!(ChannelState::decode(&buf).err(), Some(StoreError::Corrupt));
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
    assert!(open_box(&crate::crypto::Secret::from_bytes([1; 32]), &sealed).is_err());
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

/// Spec 020, R27 (the sealed state): the largest state seals, its record is
/// within 2 359 296 bytes, and it opens.
#[test]
fn s020_t27_r27_largest_state_seals_and_opens() {
    let storage_key = key(1);
    let name = DirName([2; 16]);
    let state = largest_state();
    let sealed = state.seal(&storage_key, &name, 9, 0).unwrap();
    assert!(sealed.len() - MIN_SEALED <= MAX_STATE_RECORD);
    let opened = ChannelState::open(&storage_key, &name, &sealed).unwrap();
    assert_eq!(encode(&opened).unwrap(), encode(&state).unwrap());
    let over = ChannelState {
        outbox: vec![entry(10); MAX_OUTBOX + 1],
        ..small_state()
    };
    assert_eq!(
        over.seal(&storage_key, &name, 9, 0).err(),
        Some(StoreError::OutboxFull)
    );
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

/// The encodings of a decoded list's items, to compare with a vector's.
fn encoded_items<T>(
    items: &[T],
    encode: fn(&T) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError>,
) -> Vec<Vec<u8>> {
    items
        .iter()
        .map(|item| encode(item).unwrap().to_vec())
        .collect()
}

/// Checks a state vector of `020.json`: the positive decodes to every value
/// it names and encodes back to its bytes; the negative is `Corrupt`.
fn check_state_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "state");
    let record = vector.input("record").bytes();
    let decoded = ChannelState::decode(record);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.err().unwrap());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        return;
    }
    let state = decoded.unwrap();
    let expected = |field| vector.expected(field);
    let items = |field| -> Vec<Vec<u8>> {
        expected(field)
            .list()
            .iter()
            .map(|item| item.bytes().to_vec())
            .collect()
    };
    let text = |value: &Option<String>| value.as_ref().map(|text| text.as_bytes().to_vec());
    assert_eq!(state.channel_id, expected("channel_id").array::<16>());
    assert_eq!(state.config.as_slice(), expected("config").bytes());
    assert_eq!(
        state.identity_seed.expose(),
        &expected("identity_seed").array::<32>()
    );
    assert_eq!(state.identity_epoch, expected("identity_epoch").number());
    assert_eq!(state.send_counter, expected("send_counter").u64_hex());
    assert_eq!(state.cursor, Some(expected("cursor").u64_hex()));
    let own_display_name = expected("own_display_name").bytes();
    assert_eq!(
        text(&state.own_display_name).as_deref(),
        Some(own_display_name)
    );
    assert_eq!(
        text(&state.local_name).as_deref(),
        Some(expected("local_name").bytes())
    );
    assert_eq!(
        encoded_items(&state.peers, PeerRecord::encode),
        items("peers")
    );
    assert_eq!(
        encoded_items(&state.outbox, OutboxEntry::encode),
        items("outbox")
    );
    let retiring_seed = state.retiring_seed.as_ref().map(|seed| *seed.expose());
    assert_eq!(retiring_seed, Some(expected("retiring_seed").array::<32>()));
    assert_eq!(
        encoded_items(&state.own_old_keys, OldKey::encode),
        items("own_old_keys")
    );
    assert_eq!(
        state.own_key_used_elsewhere,
        expected("own_key_used_elsewhere").flag()
    );
    assert_eq!(state.read_only, expected("read_only").flag());
    let position = (
        expected("log_committed_len").u64_hex(),
        expected("log_generation").number(),
    );
    assert_eq!(state.log_position(), position);
    assert_eq!(state.synced_at, Some(expected("synced_at").u64_hex()));
    assert_eq!(state.truncated_at, Some(expected("truncated_at").u64_hex()));
    let (log_len, generation) = state.log_position();
    assert_eq!(
        state.encode(log_len, generation).unwrap().as_slice(),
        record
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
        entries.push((name, check_state_vector));
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

proptest! {
    /// Spec 020, R29 (the items of the three lists): each re-encodes to the
    /// bytes it was decoded from, at the length `encoded_len` announced
    /// (R25). Encoding writes every field at its own key, so a decoder that
    /// put a value in the wrong field would change the bytes.
    #[test]
    fn s020_t29_r29_list_items_round_trip(
        pk in any::<[u8; 32]>(),
        label in maybe("[a-z]{0,64}"),
        flags in any::<(bool, bool, bool)>(),
        numbers in any::<(Option<u64>, u64, u64, Option<u64>, u64)>(),
        last_display_name in maybe(bytes_of(any::<u8>(), 0..=MAX_NAME)),
        client_ref in any::<[u8; 16]>(),
        kind in prop::sample::select(vec![OutboxKind::Text, OutboxKind::KeyRetired]),
        blob in bytes_of(any::<u8>(), 0..=2_000),
        signature in bytes_of(any::<u8>(), 64),
    ) {
        let (verified, muted, under_retired_key) = flags;
        let (retired_at, first_seen, last_seen, max_counter, counter) = numbers;
        let peer = PeerRecord {
            pk: PublicKey(pk),
            label,
            verified,
            muted,
            retired_at,
            first_seen,
            last_seen,
            max_counter,
            last_display_name,
        };
        let encoded = peer.encode().unwrap();
        assert_eq!((encoded.len(), encoded.capacity()), (peer.encoded_len(), peer.encoded_len()));
        assert_eq!(PeerRecord::decode(&encoded).unwrap().encode().unwrap(), encoded);
        let entry = OutboxEntry {
            client_ref,
            kind,
            sent_at: first_seen,
            blob,
            signature: Signature(signature.try_into().unwrap()),
            under_retired_key,
            counter,
        };
        let encoded = entry.encode().unwrap();
        assert_eq!((encoded.len(), encoded.capacity()), (entry.encoded_len(), entry.encoded_len()));
        assert_eq!(OutboxEntry::decode(&encoded).unwrap().encode().unwrap(), encoded);
        let old_key = OldKey { pk: PublicKey(pk), retired_at: last_seen };
        let encoded = old_key.encode().unwrap();
        assert_eq!(encoded.len(), old_key.encoded_len());
        assert_eq!(OldKey::decode(&encoded).unwrap().encode().unwrap(), encoded);
    }

    /// Spec 020, R29 (the state record): a state re-encodes to the bytes it
    /// was decoded from, and so does its `duplicate`, for every optional
    /// field present or absent and lists of a few items.
    #[test]
    fn s020_t29_r29_state_round_trip(
        seeds in any::<([u8; 32], Option<[u8; 32]>)>(),
        numbers in any::<(u32, u64, Option<u64>, u64, u32, Option<u64>, Option<u64>)>(),
        names in (maybe("[a-zà-ü]{0,32}"), maybe("[a-z ]{0,64}")),
        flags in any::<(bool, bool)>(),
        config in bytes_of(any::<u8>(), 0..=config::MAX_RECORD),
        counts in (0usize..=3, 0usize..=3, 0usize..=3),
    ) {
        let (identity_seed, retiring_seed) = seeds;
        let (identity_epoch, send_counter, cursor, log_len, generation, synced_at, truncated_at) =
            numbers;
        let (own_display_name, local_name) = names;
        let (peers, outbox, old_keys) = counts;
        let old_key = OldKey { pk: PublicKey([4; 32]), retired_at: send_counter };
        let state = ChannelState {
            channel_id: [5; 16],
            config: zeroize::Zeroizing::new(config),
            identity_seed: Secret::from_bytes(identity_seed),
            identity_epoch,
            send_counter,
            cursor,
            own_display_name,
            local_name,
            peers: vec![full_peer(3); peers],
            outbox: vec![entry(50); outbox],
            retiring_seed: retiring_seed.map(Secret::from_bytes),
            own_old_keys: vec![old_key; old_keys],
            own_key_used_elsewhere: flags.0,
            read_only: flags.1,
            log_committed_len: 0,
            log_generation: 0,
            synced_at,
            truncated_at,
        };
        let encoded = state.encode(log_len, generation).unwrap();
        let decoded = ChannelState::decode(&encoded).unwrap();
        assert_eq!(decoded.log_position(), (log_len, generation));
        assert_eq!(encode(&decoded).unwrap(), encoded);
        assert_eq!(encode(&decoded.duplicate().unwrap()).unwrap(), encoded);
    }

    /// Spec 020, R29 (the state record): the decoder never panics on
    /// arbitrary bytes, nor on a valid state with one byte changed.
    #[test]
    fn s020_t29_r29_state_never_panics(
        buf in bytes_of(any::<u8>(), 0..=1024),
        flip in any::<(usize, u8)>(),
    ) {
        let _ = ChannelState::decode(&buf);
        let some = ChannelState {
            peers: vec![full_peer(3); 2],
            outbox: vec![entry(20); 2],
            ..small_state()
        };
        let mut changed = encode(&some).unwrap().to_vec();
        let at = flip.0 % changed.len();
        changed[at] ^= flip.1;
        let _ = ChannelState::decode(&changed);
    }

    /// Spec 020, R29 (the items of the three lists): no decoder panics on
    /// arbitrary bytes.
    #[test]
    fn s020_t29_r29_list_items_never_panic(buf in bytes_of(any::<u8>(), 0..=512)) {
        let _ = PeerRecord::decode(&buf);
        let _ = OutboxEntry::decode(&buf);
        let _ = OldKey::decode(&buf);
    }
}
