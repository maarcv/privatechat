//! Tests of spec 014 R1–R8, and the dispatch of `014.json`.

use proptest::prelude::{any, proptest};

use super::{
    FP_TAG, QR_PREFIX, SHORT_WORD_COUNT, WORD_COUNT, fingerprint, parse_verify_qr, presentation,
    short_identifier, verify_qr, words,
};
use crate::Error;
use crate::crypto::{self, PublicKey, Secret};
use crate::proto::config::{ChannelId, Config};
use crate::proto::wordlist;
use crate::vectors::{self, Checker, Kind, Vector};

const CHANNEL: ChannelId = ChannelId([0x31; 16]);
const PK: PublicKey = PublicKey([0x32; 32]);

/// The `channel_id` of 011 `config_reference`, which every vector but
/// `fingerprint_other_channel` uses (spec 040-uniffi R14). Only `K_ch` and
/// the TTL derive it; the other fields are there because a config needs them.
fn reference_channel_id() -> [u8; 16] {
    let k_ch: [u8; 32] = core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap());
    let config = Config::from_parts(
        Secret::from_bytes(k_ch),
        "wss://chat.example.org:9001",
        86_400,
        "Família",
        1_790_000_000_000,
    )
    .unwrap();
    config.channel_id()
}

/// Spec 014, R1: the hash of the 17-byte tag, the 16 bytes of the channel
/// and the 32 of the key, 65 bytes with no separator. The dispatch checks
/// `fingerprint_reference`.
#[test]
fn s014_t01_r01_fingerprint_known_answer() {
    assert_eq!(FP_TAG, b"privatechat/fp/v1");
    assert_eq!(FP_TAG.len(), 17);
    let input = [FP_TAG.as_slice(), &CHANNEL.0, &PK.0].concat();
    assert_eq!(input.len(), 65);
    assert_eq!(
        fingerprint(&CHANNEL, &PK).unwrap(),
        crypto::hash(&input).unwrap()
    );
    let spec = include_str!("../../../../../docs/spec.md");
    assert!(spec.contains("`fp = BLAKE2b(\"privatechat/fp/v1\" ‖ channel_id ‖ pk_u)` (32 B)"));
}

/// Spec 014, R2: the same key in two channels has two fingerprints.
#[test]
fn s014_t02_r02_fingerprint_binds_the_channel() {
    let other = ChannelId([0x33; 16]);
    assert_ne!(
        fingerprint(&CHANNEL, &PK).unwrap(),
        fingerprint(&other, &PK).unwrap()
    );
}

/// Spec 014, R3: the prefix and 64 characters of base64url with no padding,
/// 74 bytes. The dispatch checks `qr_reference`.
#[test]
fn s014_t03_r03_qr_known_answer() {
    let qr = verify_qr(&CHANNEL, &PK).unwrap();
    assert_eq!(qr.len(), 74);
    assert_eq!(&qr[..10], QR_PREFIX);
    assert_eq!(QR_PREFIX, b"verify:v1:");
    let body = &qr[10..];
    assert_eq!(body.len(), 64);
    assert!(!body.contains(&b'='));
    let decoded = crypto::base64url_decode(body).unwrap();
    assert_eq!(decoded.as_slice(), [CHANNEL.0.as_slice(), &PK.0].concat());
}

proptest! {
    /// Spec 014, R3: a QR parses back to its key in its channel (AGENTS 21).
    #[test]
    fn s014_t03_r03_qr_round_trip(id in any::<[u8; 16]>(), pk in any::<[u8; 32]>()) {
        let channel = ChannelId(id);
        let qr = verify_qr(&channel, &PublicKey(pk)).unwrap();
        assert_eq!(parse_verify_qr(&qr, &channel).unwrap().0, pk);
    }
}

/// Spec 014, R4: each malformed QR is `BadPayload`, the prefix before the
/// channel, and one of another channel is `WrongChannel`.
#[test]
fn s014_t04_r04_rejects_a_foreign_qr() {
    let qr = verify_qr(&CHANNEL, &PK).unwrap();
    let other = ChannelId([0x33; 16]);
    let foreign = verify_qr(&other, &PK).unwrap();
    let edit = |at: usize, byte: u8| {
        let mut edited = qr.clone();
        edited[at] = byte;
        edited
    };
    for (case, bytes) in [
        ("prefix v2", [b"verify:v2:".as_slice(), &qr[10..]].concat()),
        (
            "prefix v2, another channel",
            [b"verify:v2:".as_slice(), &foreign[10..]].concat(),
        ),
        ("63 characters", qr[..73].to_vec()),
        ("65 characters", [qr.as_slice(), b"A"].concat()),
        ("a +", edit(40, b'+')),
        ("a /", edit(40, b'/')),
        ("a space", edit(40, b' ')),
        ("a trailing =", edit(73, b'=')),
        ("empty", Vec::new()),
    ] {
        assert_eq!(
            parse_verify_qr(&bytes, &CHANNEL),
            Err(Error::BadPayload),
            "{case}"
        );
    }
    for (at, byte) in qr.iter().enumerate().take(QR_PREFIX.len()) {
        let bytes = edit(at, byte ^ 0x01);
        assert_eq!(
            parse_verify_qr(&bytes, &CHANNEL),
            Err(Error::BadPayload),
            "prefix byte {at}"
        );
    }
    assert_eq!(
        parse_verify_qr(&foreign, &CHANNEL),
        Err(Error::WrongChannel)
    );
}

/// Spec 014, R5: 11 bits per word, read from the most significant bit, as
/// many words as the list has 11-bit indices. The dispatch checks the
/// `words_*` vectors: zeros, ones and the boundary at bit 131.
#[test]
fn s014_t05_r05_words_known_answer() {
    assert_eq!(1usize << 11, usize::from(wordlist::WORD_COUNT));
    // `fp[1] = 0b0010_0000`: bits 0..11 are index 1, `ability`, and the
    // second word begins at bit 11.
    let mut fp = [0; 32];
    fp[1] = 0b0010_0000;
    assert_eq!(words(&fp).unwrap()[..2], ["ability", "abandon"]);
    assert_eq!(wordlist::word(1), Some("ability"));
}

/// Spec 014, R6: the short identifier is words 0 to 3.
#[test]
fn s014_t06_r06_short_identifier_is_the_first_four() {
    let words = words(&fingerprint(&CHANNEL, &PK).unwrap()).unwrap();
    let short = short_identifier(&words);
    assert_eq!(SHORT_WORD_COUNT, 4);
    assert_eq!(short, words[..4]);
}

/// Spec 014, R8: `presentation` is its three parts, with 12 and 4 words.
#[test]
fn s014_t08_r08_presentation_matches_its_parts() {
    let presentation = presentation(&CHANNEL, &PK).unwrap();
    let words = words(&fingerprint(&CHANNEL, &PK).unwrap()).unwrap();
    assert_eq!(presentation.words, words);
    assert_eq!(presentation.short, short_identifier(&words));
    assert_eq!(presentation.qr, verify_qr(&CHANNEL, &PK).unwrap());
    assert_eq!(
        (presentation.words.len(), presentation.short.len()),
        (12, 4)
    );
}

/// The key of `fingerprint_reference` and `qr_reference`, the Ed25519 key
/// of the script's seed `0xc0..0xe0`.
fn reference_pk() -> PublicKey {
    let seed: [u8; 32] = core::array::from_fn(|i| 0xc0 + u8::try_from(i).unwrap());
    crypto::sign_keypair_from_seed(&Secret::from_bytes(seed))
        .unwrap()
        .0
}

/// `fingerprint_reference`: `fp` of the reference key in the reference
/// channel (R1).
fn check_fingerprint_reference(vector: &Vector) {
    let channel = ChannelId(vector.input("channel_id").array());
    assert_eq!(channel.0, reference_channel_id());
    let pk = PublicKey(vector.input("pk_u").array());
    assert_eq!(pk.0, reference_pk().0);
    assert_eq!(
        fingerprint(&channel, &pk).unwrap(),
        vector.expected("fp").array()
    );
}

/// `fingerprint_other_channel`: the same key in another channel (R2).
fn check_fingerprint_other_channel(vector: &Vector) {
    let channel = ChannelId(vector.input("channel_id").array());
    assert_ne!(channel.0, reference_channel_id());
    let pk = PublicKey(vector.input("pk_u").array());
    assert_eq!(pk.0, reference_pk().0);
    assert_eq!(
        fingerprint(&channel, &pk).unwrap(),
        vector.expected("fp").array()
    );
}

/// `words_*`: the 12 indices and words of a fingerprint (R5); those of
/// `words_reference` are of `fingerprint_reference` (spec 040-uniffi R14).
fn check_words(vector: &Vector) {
    let fp = vector.input("fp").array();
    if vector.name() == "words_reference" {
        let channel = ChannelId(reference_channel_id());
        assert_eq!(fp, fingerprint(&channel, &reference_pk()).unwrap());
    }
    let words = words(&fp).unwrap();
    let expected: Vec<&str> = vector
        .expected("words")
        .list()
        .iter()
        .map(|word| word.text())
        .collect();
    assert_eq!(words.as_slice(), expected, "{}", vector.name());
    let indices = vector.expected("indices").list();
    assert_eq!(indices.len(), WORD_COUNT, "{}", vector.name());
    for (index, word) in indices.iter().zip(words) {
        let index = u16::try_from(index.number()).unwrap();
        assert_eq!(wordlist::word(index), Some(word), "{}", vector.name());
    }
}

/// `qr_reference`: the QR of the reference key, which parses back to it (R3,
/// R4).
fn check_qr(vector: &Vector) {
    let channel = ChannelId(vector.input("channel_id").array());
    assert_eq!(channel.0, reference_channel_id());
    let pk = PublicKey(vector.input("pk_u").array());
    assert_eq!(pk.0, reference_pk().0);
    let qr = verify_qr(&channel, &pk).unwrap();
    assert_eq!(qr, vector.expected("qr").bytes());
    assert_eq!(parse_verify_qr(&qr, &channel).unwrap().0, pk.0);
}

/// `qr_*` negatives: the error of R4, scanned in the reference channel.
fn check_bad_qr(vector: &Vector) {
    assert_eq!(vector.kind(), Kind::Negative);
    let channel = ChannelId(vector.input("channel_id").array());
    assert_eq!(channel.0, reference_channel_id());
    let error = parse_verify_qr(vector.input("qr").bytes(), &channel).expect_err(vector.name());
    assert_eq!(
        format!("{error:?}"),
        vector.expected("error").text(),
        "{}",
        vector.name()
    );
}

/// Spec 015, R3: every vector of `014.json` is checked once.
#[test]
fn s014_vectors_dispatch() {
    let words = [
        "words_reference",
        "words_zero",
        "words_ones",
        "words_bit_131",
    ];
    let bad_qrs = [
        "qr_wrong_prefix",
        "qr_wrong_length",
        "qr_standard_base64",
        "qr_padding",
        "qr_other_channel",
    ];
    let entries = [
        &[
            (
                "fingerprint_reference",
                check_fingerprint_reference as Checker,
            ),
            ("fingerprint_other_channel", check_fingerprint_other_channel),
        ],
        words.map(|name| (name, check_words as Checker)).as_slice(),
        &[("qr_reference", check_qr as Checker)],
        bad_qrs
            .map(|name| (name, check_bad_qr as Checker))
            .as_slice(),
    ]
    .concat();
    vectors::check_all("014", &entries);
}
