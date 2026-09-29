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
use crate::vectors::{self, Checker, Vector};

const CHANNEL: ChannelId = ChannelId([0x31; 16]);
const PK: PublicKey = PublicKey([0x32; 32]);

/// The `channel_id` of 011 `config_reference`, which every vector but the
/// other-channel ones uses (spec 040-uniffi R14).
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

/// Spec 014, R4: each malformed QR is `BadPayload`, and one of another
/// channel is `WrongChannel`.
#[test]
fn s014_t04_r04_rejects_a_foreign_qr() {
    let qr = verify_qr(&CHANNEL, &PK).unwrap();
    let body = &qr[10..];
    let edit = |at: usize, byte: u8| {
        let mut edited = qr.clone();
        edited[at] = byte;
        edited
    };
    for (case, bytes) in [
        ("prefix v2", [b"verify:v2:".as_slice(), body].concat()),
        ("63 characters", qr[..73].to_vec()),
        ("65 characters", [qr.as_slice(), b"A"].concat()),
        ("a +", edit(40, b'+')),
        ("a /", edit(40, b'/')),
        ("a trailing =", edit(73, b'=')),
        ("empty", Vec::new()),
    ] {
        assert_eq!(
            parse_verify_qr(&bytes, &CHANNEL),
            Err(Error::BadPayload),
            "{case}"
        );
    }
    let other = ChannelId([0x33; 16]);
    assert_eq!(parse_verify_qr(&qr, &other), Err(Error::WrongChannel));
}

/// Spec 014, R5: 11 bits per word from the most significant bit; zeros are
/// 12 × `abandon`, ones 12 × `zoo`, and bit 131 is the last one read. The
/// dispatch checks the `words_*` vectors.
#[test]
fn s014_t05_r05_words_known_answer() {
    assert_eq!(words(&[0; 32]).unwrap(), ["abandon"; WORD_COUNT]);
    assert_eq!(words(&[0xff; 32]).unwrap(), ["zoo"; WORD_COUNT]);
    let mut fp = [0xff; 32];
    fp[..16].fill(0);
    fp[16] = 0x17;
    let expected: [&str; WORD_COUNT] =
        core::array::from_fn(|i| if i == 11 { "ability" } else { "abandon" });
    assert_eq!(words(&fp).unwrap(), expected);
    // `fp[0] = 0b0000_0000`, `fp[1] = 0b0010_0000`: the first word is index
    // 1, `ability`, and the second begins at bit 11.
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

/// `fingerprint_*`: `fp` of a channel and a key (R1, R2).
fn check_fingerprint(vector: &Vector) {
    let channel = ChannelId(vector.input("channel_id").array());
    if vector.name() == "fingerprint_reference" {
        assert_eq!(channel.0, reference_channel_id());
    }
    let pk = PublicKey(vector.input("pk_u").array());
    assert_eq!(
        fingerprint(&channel, &pk).unwrap(),
        vector.expected("fp").array()
    );
}

/// `words_*`: the indices and the words of a fingerprint (R5).
fn check_words(vector: &Vector) {
    let fp = vector.input("fp").array();
    let expected: Vec<&str> = vector
        .expected("words")
        .list()
        .iter()
        .map(|word| word.text())
        .collect();
    assert_eq!(
        words(&fp).unwrap().as_slice(),
        expected,
        "{}",
        vector.name()
    );
    for (index, word) in vector.expected("indices").list().iter().zip(&expected) {
        let index = u16::try_from(index.number()).unwrap();
        assert_eq!(wordlist::word(index), Some(*word));
    }
}

/// `qr_reference`: the QR bytes, which parse back to the key (R3, R4).
fn check_qr(vector: &Vector) {
    let channel = ChannelId(vector.input("channel_id").array());
    assert_eq!(channel.0, reference_channel_id());
    let pk = PublicKey(vector.input("pk_u").array());
    let qr = verify_qr(&channel, &pk).unwrap();
    assert_eq!(qr, vector.expected("qr").bytes());
    assert_eq!(parse_verify_qr(&qr, &channel).unwrap().0, pk.0);
}

/// `qr_*` negatives: the error of R4 in the reference channel.
fn check_bad_qr(vector: &Vector) {
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
    let fingerprints = ["fingerprint_reference", "fingerprint_other_channel"];
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
        fingerprints
            .map(|name| (name, check_fingerprint as Checker))
            .as_slice(),
        words.map(|name| (name, check_words as Checker)).as_slice(),
        &[("qr_reference", check_qr as Checker)],
        bad_qrs
            .map(|name| (name, check_bad_qr as Checker))
            .as_slice(),
    ]
    .concat();
    vectors::check_all("014", &entries);
}
