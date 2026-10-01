//! Tests of spec 020 over the records `core` seals and opens.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, prop, proptest};

use super::state::items::{
    MAX_BLOB, MAX_OLD_KEY, MAX_OUTBOX_ENTRY, MAX_PEER_RECORD, OldKey, OutboxEntry, OutboxKind,
    PeerRecord,
};
use super::{MAX_NAME, StoreError};
use crate::crypto::{PublicKey, Signature};
use crate::proto::record::ITEM_HEADER_LEN;

/// One field: key ‖ 4-byte big-endian length ‖ value (spec 017 R1).
fn field(key: u8, value: &[u8]) -> Vec<u8> {
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

    /// Spec 020, R29 (the items of the three lists): no decoder panics on
    /// arbitrary bytes.
    #[test]
    fn s020_t29_r29_list_items_never_panic(buf in bytes_of(any::<u8>(), 0..=512)) {
        let _ = PeerRecord::decode(&buf);
        let _ = OutboxEntry::decode(&buf);
        let _ = OldKey::decode(&buf);
    }
}
