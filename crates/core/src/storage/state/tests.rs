//! Tests of spec 020 over the state record and the items of its lists.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, prop, proptest};

use super::super::tests::{field, fields, key, list_value, replaced, without};
use super::super::{DirName, MAX_NAME, MIN_SEALED, StoreError};
use super::items::{
    MAX_BLOB, MAX_OLD_KEY, MAX_OUTBOX_ENTRY, MAX_PEER_RECORD, OldKey, OutboxEntry, OutboxKind,
    PeerRecord,
};
use super::{ChannelState, MAX_OLD_KEYS, MAX_OUTBOX, MAX_PEERS, MAX_STATE_RECORD};
use crate::crypto::{PublicKey, Secret, Signature};
use crate::proto::config;
use crate::proto::record::ITEM_HEADER_LEN;
use crate::testing::state_eq;
use crate::vectors::{Kind, Vector};

/// A peer with every field present, names at `name_len` bytes.
pub(in crate::storage) fn full_peer(name_len: usize) -> PeerRecord {
    PeerRecord {
        pk: PublicKey([1; 32]),
        label: Some("l".repeat(name_len)),
        verified: true,
        muted: false,
        retired_at: Some(2),
        first_seen: 3,
        last_seen: 4,
        max_counter: Some(5),
        last_display_name: Some(zeroize::Zeroizing::new(vec![b'n'; name_len])),
    }
}

/// An `outbox` entry whose blob has `blob_len` bytes.
pub(in crate::storage) fn entry(blob_len: usize) -> OutboxEntry {
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
    // A blob one byte over, planted at key 3; the entry's own bound refuses
    // it as well, since every other key is fixed-width.
    let buf = entry(MAX_BLOB).encode().unwrap().to_vec();
    let long_blob = replaced(&buf, 3, &vec![8; MAX_BLOB + 1]);
    assert_eq!(long_blob.len(), buf.len() + 1);
    let error = OutboxEntry::decode(&long_blob).err();
    assert_eq!(error, Some(StoreError::Corrupt));
}

/// Spec 020, R8 (the items of the three lists): each key lands in its own
/// field, over records built by hand with a distinct value per key, so that
/// an encoder and a decoder that swapped two fields alike would fail.
#[test]
fn s020_t08_r08_list_items_by_key() {
    let peer = [
        field(0, &[1; 32]),
        field(1, b"label"),
        field(2, &[1]),
        field(3, &[0]),
        field(4, &4u64.to_be_bytes()),
        field(5, &5u64.to_be_bytes()),
        field(6, &6u64.to_be_bytes()),
        field(7, &7u64.to_be_bytes()),
        field(8, b"name"),
    ]
    .concat();
    let decoded = PeerRecord::decode(&peer).unwrap();
    assert_eq!(decoded.pk.0, [1; 32]);
    assert_eq!(decoded.label.as_deref(), Some("label"));
    assert_eq!((decoded.verified, decoded.muted), (true, false));
    assert_eq!(decoded.retired_at, Some(4));
    assert_eq!((decoded.first_seen, decoded.last_seen), (5, 6));
    assert_eq!(decoded.max_counter, Some(7));
    let name = decoded
        .last_display_name
        .as_ref()
        .map(|name| name.as_slice());
    assert_eq!(name, Some(&b"name"[..]));
    assert_eq!(decoded.encode().unwrap().as_slice(), peer);
    let entry = [
        field(0, &[2; 16]),
        field(1, &[1]),
        field(2, &2u64.to_be_bytes()),
        field(3, b"blob"),
        field(4, &[4; 64]),
        field(5, &[1]),
        field(6, &6u64.to_be_bytes()),
    ]
    .concat();
    let decoded = OutboxEntry::decode(&entry).unwrap();
    assert_eq!(decoded.client_ref, [2; 16]);
    assert_eq!(decoded.kind, OutboxKind::KeyRetired);
    assert_eq!((decoded.sent_at, decoded.counter), (2, 6));
    assert_eq!(decoded.blob, b"blob");
    assert_eq!(decoded.signature.0, [4; 64]);
    assert!(decoded.under_retired_key);
    assert_eq!(decoded.encode().unwrap().as_slice(), entry);
    let old_key = [field(0, &[3; 32]), field(1, &1u64.to_be_bytes())].concat();
    let decoded = OldKey::decode(&old_key).unwrap();
    assert_eq!((decoded.pk.0, decoded.retired_at), ([3; 32], 1));
    assert_eq!(decoded.encode().unwrap().as_slice(), old_key);
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
pub(in crate::storage) fn small_state() -> ChannelState {
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
pub(in crate::storage) fn largest_state() -> ChannelState {
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
pub(in crate::storage) fn encode(
    state: &ChannelState,
) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
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
    for version in [0, 2, 255] {
        let mut other = with_unknown.clone();
        other[5] = version;
        let error = ChannelState::decode(&other).err();
        assert_eq!(error, Some(StoreError::UnsupportedVersion), "{version}");
    }
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

/// A state with every optional field present and one item in each list.
fn full_state() -> ChannelState {
    ChannelState {
        cursor: Some(1),
        own_display_name: Some("own".to_owned()),
        local_name: Some("local".to_owned()),
        peers: vec![full_peer(3)],
        outbox: vec![entry(10)],
        retiring_seed: Some(Secret::from_bytes([5; 32])),
        own_old_keys: vec![OldKey {
            pk: PublicKey([4; 32]),
            retired_at: 5,
        }],
        synced_at: Some(2),
        truncated_at: Some(3),
        ..small_state()
    }
}

/// Spec 020, R8 (the state record and its items): each mandatory key, and
/// only those, cannot be left out; the optional ones can.
#[test]
fn s020_t08_r08_mandatory_keys() {
    type Decode = fn(&[u8]) -> Option<StoreError>;
    let state = encode(&full_state()).unwrap().to_vec();
    let old_key = &fields(&state)
        .into_iter()
        .find(|(key, _)| *key == 12)
        .unwrap()
        .1;
    let old_key = &old_key[4..];
    let peer = full_peer(3).encode().unwrap().to_vec();
    let outbox = entry(10).encode().unwrap().to_vec();
    /// A record, its decoder, its mandatory keys and its optional ones.
    type Schema<'a> = (&'a [u8], Decode, &'a [u8], &'a [u8]);
    let schemas: [Schema; 4] = [
        (
            &state,
            |buf| ChannelState::decode(buf).err(),
            &[0, 1, 2, 3, 4, 5, 9, 10, 12, 13, 14, 15, 16],
            &[6, 7, 8, 11, 17, 18],
        ),
        (
            &peer,
            |buf| PeerRecord::decode(buf).err(),
            &[0, 2, 3, 5, 6],
            &[1, 4, 7, 8],
        ),
        (
            &outbox,
            |buf| OutboxEntry::decode(buf).err(),
            &[0, 1, 2, 3, 4, 5, 6],
            &[],
        ),
        (old_key, |buf| OldKey::decode(buf).err(), &[0, 1], &[]),
    ];
    for (buf, decode, mandatory, optional) in schemas {
        assert_eq!(decode(buf), None);
        for key in mandatory {
            assert_eq!(
                decode(&without(buf, *key)),
                Some(StoreError::Corrupt),
                "key {key}"
            );
        }
        for key in optional {
            assert_eq!(decode(&without(buf, *key)), None, "key {key}");
        }
    }
}

/// Spec 020, R10: `duplicate` keeps the log position, which `state_eq`
/// leaves out.
#[test]
fn s020_t10_r10_duplicate_keeps_the_log_position() {
    let state = ChannelState {
        log_committed_len: 123,
        log_generation: 4,
        ..full_state()
    };
    assert_eq!(state.duplicate().log_position(), (123, 4));
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
    let long_own_name = ChannelState {
        own_display_name: Some("o".repeat(MAX_NAME + 1)),
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
        long_own_name,
        long_config,
        long_label,
    ] {
        assert_eq!(encode(&state).err(), Some(StoreError::Corrupt));
    }
    // The same bounds on open, each value planted in a valid record.
    let record = encode(&small_state()).unwrap().to_vec();
    let entry = entry(10).encode().unwrap().to_vec();
    let old_key = OldKey {
        pk: PublicKey([4; 32]),
        retired_at: 5,
    };
    let old_key = old_key.encode().unwrap().to_vec();
    let name = vec![b'n'; MAX_NAME];
    let planted: [(u8, Vec<u8>, Vec<u8>); 5] = [
        (
            2,
            vec![2; config::MAX_RECORD],
            vec![2; config::MAX_RECORD + 1],
        ),
        (7, name.clone(), [&name[..], b"n"].concat()),
        (8, name.clone(), [&name[..], b"n"].concat()),
        (
            10,
            list_value(&vec![entry.clone(); MAX_OUTBOX]),
            list_value(&vec![entry; MAX_OUTBOX + 1]),
        ),
        (
            12,
            list_value(&vec![old_key.clone(); MAX_OLD_KEYS]),
            list_value(&vec![old_key; MAX_OLD_KEYS + 1]),
        ),
    ];
    for (key, at_limit, over) in planted {
        assert!(
            ChannelState::decode(&replaced(&record, key, &at_limit)).is_ok(),
            "key {key}"
        );
        let error = ChannelState::decode(&replaced(&record, key, &over)).err();
        assert_eq!(error, Some(StoreError::Corrupt), "key {key}");
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
pub(in crate::storage) fn check_state_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "state");
    let record = vector.input("record").bytes();
    let decoded = ChannelState::decode(record);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.err().unwrap());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        // `Corrupt` says nothing of the rule: the bytes say which one broke.
        let reference = crate::vectors::load("020", "state_reference");
        let edited = [reference.input("record").bytes(), &field(19, &[])].concat();
        assert_eq!(record, edited.as_slice(), "{}", vector.name());
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
            last_display_name: last_display_name.map(zeroize::Zeroizing::new),
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
        assert!(state_eq(&decoded.duplicate(), &state));
        // `open(seal(x))` gives `x`, field by field.
        let (storage_key, name) = (key(1), DirName([2; 16]));
        let sealed = state.seal(&storage_key, &name, log_len, generation).unwrap();
        let opened = ChannelState::open(&storage_key, &name, &sealed).unwrap();
        assert!(state_eq(&opened, &state));
        assert_eq!(opened.log_position(), (log_len, generation));
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
