//! Tests of spec 012 R4, R5: the header's bytes and its keystream.

use proptest::prelude::{any, proptest};

use super::{ENC_HDR_LEN, HEADER_STREAM_LEN, Header, header_keystream};
use crate::crypto::{self, Nonce, PublicKey, Secret};
use crate::proto::keys::ChannelKeys;

const NONCE: Nonce = Nonce([0x3c; 24]);

fn keys(k_ch: u8) -> ChannelKeys {
    ChannelKeys::derive(&Secret::from_bytes([k_ch; 32])).unwrap()
}

/// Spec 012, R4: the keystream is `stream_xor(K_hdr, nonce)` over 104 zero
/// bytes; its first 40 bytes seal a header and open it again. The known
/// answer is the `header_sealed` vector of the dispatch.
#[test]
fn s012_t05_r04_header_and_mask_known_answer() {
    let keys = keys(0x41);
    let stream = header_keystream(&keys, &NONCE).unwrap();
    let mut expected = [0u8; HEADER_STREAM_LEN];
    crypto::stream_xor(&keys.hdr, &NONCE, &mut expected).unwrap();
    assert_eq!(stream, expected);
    assert_eq!(HEADER_STREAM_LEN - ENC_HDR_LEN, 64, "the signature mask");
    let header = Header {
        sender_pk: PublicKey([0x99; 32]),
        counter: 42,
    };
    let mut sealed = header.to_bytes();
    for (byte, mask) in sealed.iter_mut().zip(&stream) {
        *byte ^= mask;
    }
    assert_ne!(sealed, header.to_bytes());
    for (byte, mask) in sealed.iter_mut().zip(&stream) {
        *byte ^= mask;
    }
    assert_eq!(Header::from_bytes(&sealed), header);
    let other_nonce = header_keystream(&keys, &Nonce([0x3d; 24])).unwrap();
    assert_ne!(stream, other_nonce);
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

/// Spec 012, R5: under another `K_hdr` every byte of the keystream is
/// different, and the header still decodes, to a key nobody holds.
#[test]
fn s012_t07_r05_a_wrong_key_decodes_without_error() {
    let right = header_keystream(&keys(0x41), &NONCE).unwrap();
    let wrong = header_keystream(&keys(0x42), &NONCE).unwrap();
    assert_ne!(right, wrong);
    let header = Header {
        sender_pk: PublicKey([0x99; 32]),
        counter: 42,
    };
    let mut enc_hdr = header.to_bytes();
    for (byte, mask) in enc_hdr.iter_mut().zip(&right) {
        *byte ^= mask;
    }
    let mut opened = enc_hdr;
    for (byte, mask) in opened.iter_mut().zip(&wrong) {
        *byte ^= mask;
    }
    let decoded = Header::from_bytes(&opened);
    assert_ne!(decoded, header);
}
