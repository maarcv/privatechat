//! Tests of spec 012 R1–R3, R6, R7, and the dispatch of `012.json`.

use super::{CONTEXT_HEADER, CONTEXT_MESSAGE, ChannelKeys, message_key};
use crate::crypto::{self, PublicKey, SECRET_TYPES, Secret};
use crate::proto::header::{ENC_HDR_LEN, Header, header_keystream};
use crate::vectors::{self, Checker, Vector};

const K_CH: [u8; 32] = [0x5c; 32];

fn keys() -> ChannelKeys {
    ChannelKeys::derive(&Secret::from_bytes(K_CH)).unwrap()
}

/// The 40 bytes `pk_u ‖ BE64(counter)`, built apart from `message_key`.
fn input(pk: &[u8; 32], counter: u64) -> Vec<u8> {
    [pk.as_slice(), &counter.to_be_bytes()].concat()
}

/// Spec 012, R1: each master key is the KDF of `K_ch` under its context,
/// and the two contexts give different keys.
#[test]
fn s012_t01_r01_master_keys_known_answer() {
    let keys = keys();
    let k_ch = Secret::from_bytes(K_CH);
    assert!(keys.msg == crypto::kdf_derive(&k_ch, &CONTEXT_MESSAGE).unwrap());
    assert!(keys.hdr == crypto::kdf_derive(&k_ch, &CONTEXT_HEADER).unwrap());
    assert!(keys.msg != keys.hdr);
}

/// Spec 012, R2: `mk` is the keyed hash of exactly the 40 bytes of the
/// sender's key and the big-endian counter, at the ends of the counter too.
/// The known answers are the `message_key_*` vectors of the dispatch.
#[test]
fn s012_t02_r02_message_key_known_answer() {
    let keys = keys();
    let pk = [0x17; 32];
    for counter in [0, 1, 0x0102_0304_0506_0708, u64::MAX] {
        let expected = crypto::keyed_hash(&keys.msg, &input(&pk, counter)).unwrap();
        assert_eq!(input(&pk, counter).len(), 40);
        assert!(
            message_key(&keys, &PublicKey(pk), counter).unwrap() == expected,
            "{counter}"
        );
    }
}

/// Spec 012, R2: another sender or a counter one apart gives another key.
#[test]
fn s012_t03_r02_message_key_changes_with_every_input() {
    let keys = keys();
    let base = message_key(&keys, &PublicKey([1; 32]), 7).unwrap();
    assert!(message_key(&keys, &PublicKey([2; 32]), 7).unwrap() != base);
    assert!(message_key(&keys, &PublicKey([1; 32]), 8).unwrap() != base);
    assert!(message_key(&keys, &PublicKey([1; 32]), 6).unwrap() != base);
}

/// Spec 012, R3: `mk` is keyed with `K_msg`, never with `K_ch`.
#[test]
fn s012_t04_r03_message_key_comes_from_k_msg() {
    let keys = keys();
    let pk = [0x21; 32];
    let mk = message_key(&keys, &PublicKey(pk), 3).unwrap();
    assert!(mk == crypto::keyed_hash(&keys.msg, &input(&pk, 3)).unwrap());
    let k_ch = Secret::from_bytes(K_CH);
    assert!(mk != crypto::keyed_hash(&k_ch, &input(&pk, 3)).unwrap());
}

/// Spec 012, R6: no new secret type, and the keys never print.
#[test]
fn s012_t08_r06_no_new_secret_type() {
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>"]);
    let keys = keys();
    let debug = format!("{keys:?}");
    assert_eq!(debug, "ChannelKeys { msg: [REDACTED], hdr: [REDACTED] }");
}

/// Spec 012, R7: the contexts are the literals of `docs/spec.md` §4.
#[test]
fn s012_t09_r07_contexts_are_the_literals() {
    assert_eq!(format!("{CONTEXT_MESSAGE:?}"), "6d73676b65795f5f"); // "msgkey__"
    assert_eq!(format!("{CONTEXT_HEADER:?}"), "63686864725f5f5f"); // "chhdr___"
    let spec = include_str!("../../../../../docs/spec.md");
    assert!(spec.contains("`chauth__`, `msgkey__`, `chhdr___`"));
}

fn check_master_keys(vector: &Vector) {
    let keys = ChannelKeys::derive(&Secret::from_bytes(vector.input("k_ch").array())).unwrap();
    assert_eq!(keys.msg.expose(), &vector.expected("k_msg").array());
    assert_eq!(keys.hdr.expose(), &vector.expected("k_hdr").array());
}

fn check_message_key(vector: &Vector) {
    let keys = ChannelKeys::derive(&Secret::from_bytes(vector.input("k_ch").array())).unwrap();
    let pk = PublicKey(vector.input("pk_u").array());
    let mk = message_key(&keys, &pk, vector.input("counter").u64_hex()).unwrap();
    assert_eq!(
        mk.expose(),
        &vector.expected("mk").array(),
        "{}",
        vector.name()
    );
}

/// The header, its keystream, and the two XORs spec 013 applies to the
/// header and to the signature (R4).
fn check_header_sealed(vector: &Vector) {
    let keys = ChannelKeys::derive(&Secret::from_bytes(vector.input("k_ch").array())).unwrap();
    assert_eq!(keys.hdr.expose(), &vector.expected("k_hdr").array());
    let header = Header {
        sender_pk: PublicKey(vector.input("sender_pk").array()),
        counter: vector.input("counter").u64_hex(),
    };
    assert_eq!(
        header.to_bytes().as_slice(),
        vector.expected("header").bytes()
    );
    let nonce = crypto::Nonce(vector.input("nonce").array());
    let stream = header_keystream(&keys, &nonce).unwrap();
    assert_eq!(stream.as_slice(), vector.expected("keystream").bytes());
    let (header_mask, signature_mask) = stream.split_at(ENC_HDR_LEN);
    let xor = |data: &[u8], mask: &[u8]| -> Vec<u8> {
        data.iter().zip(mask).map(|(a, b)| a ^ b).collect()
    };
    let enc_hdr = xor(&header.to_bytes(), header_mask);
    assert_eq!(enc_hdr, vector.expected("enc_hdr").bytes());
    let masked = xor(vector.input("signature").bytes(), signature_mask);
    assert_eq!(masked, vector.expected("masked_signature").bytes());
    let opened: [u8; ENC_HDR_LEN] = xor(&enc_hdr, header_mask).try_into().unwrap();
    assert_eq!(Header::from_bytes(&opened), header);
}

/// Spec 015, R3: every vector of `012.json` is checked once.
#[test]
fn s012_vectors_dispatch() {
    let message_keys = [
        "message_key_c0",
        "message_key_c1",
        "message_key_max",
        "message_key_other_sender",
    ];
    let entries = [
        &[("master_keys", check_master_keys as Checker)][..],
        message_keys
            .map(|name| (name, check_message_key as Checker))
            .as_slice(),
        &[("header_sealed", check_header_sealed as Checker)],
    ]
    .concat();
    vectors::check_all("012", &entries);
}
