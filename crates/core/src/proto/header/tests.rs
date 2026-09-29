//! Tests of spec 012 R4, R5: the header's bytes and its keystream.

use proptest::prelude::{any, proptest};

use super::{ENC_HDR_LEN, HEADER_STREAM_LEN, Header, header_keystream};
use crate::crypto::{self, Nonce, PublicKey, Secret};
use crate::proto::keys::ChannelKeys;

const NONCE: Nonce = Nonce([0x3c; 24]);

fn keys(k_ch: [u8; 32]) -> ChannelKeys {
    ChannelKeys::derive(&Secret::from_bytes(k_ch)).unwrap()
}

/// `bytes` XORed with the first `N` bytes of `mask`.
fn xor<const N: usize>(mut bytes: [u8; N], mask: &[u8]) -> [u8; N] {
    for (byte, mask) in bytes.iter_mut().zip(mask) {
        *byte ^= mask;
    }
    bytes
}

/// Spec 012, R4: the keystream is `stream_xor(K_hdr, nonce)` over 104 zero
/// bytes, changes with the nonce, and its last 64 bytes mask the signature.
/// The dispatch checks `header_sealed`: its `K_hdr`, keystream, `enc_hdr`
/// and masked signature.
#[test]
fn s012_t05_r04_header_and_mask_known_answer() {
    let keys = keys([0x41; 32]);
    let stream = header_keystream(&keys, &NONCE).unwrap();
    let mut expected = [0u8; HEADER_STREAM_LEN];
    crypto::stream_xor(&keys.hdr, &NONCE, &mut expected).unwrap();
    assert_eq!(stream, expected);
    assert_eq!(HEADER_STREAM_LEN - ENC_HDR_LEN, 64, "the signature mask");
    assert_ne!(stream, header_keystream(&keys, &Nonce([0x3d; 24])).unwrap());
}

proptest! {
    /// Spec 012, R4: `to_bytes` is `sender_pk ‖ BE64(counter)`, and
    /// `from_bytes` gives back the same header.
    #[test]
    fn s012_t06_r04_header_bytes_round_trip(pk in any::<[u8; 32]>(), counter in any::<u64>()) {
        let header = Header { sender_pk: PublicKey(pk), counter };
        let bytes = header.to_bytes();
        assert_eq!(bytes.as_slice(), [pk.as_slice(), &counter.to_be_bytes()].concat());
        assert_eq!(Header::from_bytes(&bytes), header);
    }
}

/// Spec 012, R5: under another `K_hdr` the keystream differs in each of its
/// 104 bytes (for these two keys), and the header still decodes, to a key
/// nobody holds.
#[test]
fn s012_t07_r05_a_wrong_key_decodes_without_error() {
    let right = header_keystream(&keys([0x41; 32]), &NONCE).unwrap();
    let wrong = header_keystream(&keys([0x42; 32]), &NONCE).unwrap();
    assert!(right.iter().zip(&wrong).all(|(a, b)| a != b));
    let header = Header {
        sender_pk: PublicKey([0x99; 32]),
        counter: 42,
    };
    let decoded = Header::from_bytes(&xor(xor(header.to_bytes(), &right), &wrong));
    assert_ne!(decoded, header);
}
