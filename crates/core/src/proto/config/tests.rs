use proptest::collection::vec as bytes_of;
use proptest::prelude::{any, proptest};

use super::{CHANNEL_AUTH_CONTEXT, CHANNEL_ID_TAG, Config, MAX_QR, MAX_RECORD, base64url, url};
use crate::Error;
use crate::crypto::{self, SECRET_TYPES, Secret, ct_eq};
use crate::vectors::{self, Checker, Kind, Vector};

const K_CH: [u8; 32] = [0xa5; 32];
const NOW: u64 = 1_790_000_060_000;

/// `key` ‖ `len` ‖ `value`, built by hand so that the tests do not depend on
/// the writer they check.
fn field(key: u8, value: &[u8]) -> Vec<u8> {
    let len = u32::try_from(value.len()).unwrap().to_be_bytes();
    [&[key][..], &len, value].concat()
}

/// A valid config without key 6, as `(key, value)` pairs in key order.
fn fields() -> Vec<(u8, Vec<u8>)> {
    vec![
        (0, vec![1]),
        (1, vec![1]),
        (2, K_CH.to_vec()),
        (3, b"wss://host".to_vec()),
        (4, 86_400u32.to_be_bytes().to_vec()),
        (5, NOW.to_be_bytes().to_vec()),
        (7, b"name".to_vec()),
    ]
}

fn encode(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|(key, value)| field(*key, value))
        .collect()
}

/// The record of `fields()` with `key` set to `value`, inserted in order.
fn with(key: u8, value: &[u8]) -> Vec<u8> {
    let mut edited: Vec<_> = fields().into_iter().filter(|(k, _)| *k != key).collect();
    edited.push((key, value.to_vec()));
    edited.sort_by_key(|(k, _)| *k);
    encode(&edited)
}

fn without(key: u8) -> Vec<u8> {
    let kept: Vec<_> = fields().into_iter().filter(|(k, _)| *k != key).collect();
    encode(&kept)
}

fn rejection(record: &[u8]) -> Option<Error> {
    Config::parse(record, NOW).err()
}

fn reference() -> Config {
    Config::from_parts(Secret::copy_from(&K_CH), "wss://host", 86_400, "name", NOW).unwrap()
}

/// Records that break the strict decode of R2.
fn malformed() -> Vec<Vec<u8>> {
    let mut swapped = fields();
    swapped.swap(3, 4);
    let mut repeated = fields();
    repeated.push((7, b"name".to_vec()));
    vec![
        encode(&swapped),
        encode(&repeated),
        [encode(&fields()), field(8, b"x")].concat(),
        without(2),
        with(2, &[0; 31]),
        with(4, &[0, 1, 0]),
        with(7, &[0xff]),
        [encode(&fields()), vec![0]].concat(),
    ]
}

/// Records whose versions R3 rejects, some with a broken tail after key 1.
fn unsupported() -> Vec<Vec<u8>> {
    let tail = |version: u8| [field(0, &[version]), field(1, &[1]), vec![0xff, 0]].concat();
    vec![
        with(0, &[0]),
        with(0, &[2]),
        with(1, &[2]),
        [with(0, &[2]), field(8, b"x")].concat(),
        tail(2),
        tail(0),
    ]
}

/// Records out of the ranges of R4.
fn out_of_range() -> Vec<Vec<u8>> {
    vec![
        with(4, &59u32.to_be_bytes()),
        with(4, &2_592_001u32.to_be_bytes()),
        with(7, &[b'a'; 65]),
        with(7, "a\u{0}b".as_bytes()),
        with(7, "a\u{85}b".as_bytes()),
    ]
}

/// A v3 onion host: 56 characters of `a-z` and `2-7`, then `.onion`.
fn onion(label_len: usize, character: char) -> String {
    format!("{}.onion", character.to_string().repeat(label_len))
}

/// Server URLs outside the grammar of R5.
fn bad_urls() -> Vec<String> {
    let mut urls: Vec<String> = [
        "",
        "wss://",
        "ws://host",
        "wss://host/path",
        "wss://host/",
        "wss://host?q",
        "wss://HOST",
        "wss://host:",
        "wss://host:0",
        "wss://host:065",
        "wss://host:443",
        "wss://host:65536",
        "wss://host:9001:1",
        "wss://host:+9001",
        "wss://user@host",
        "wss://[::1]",
        "https://host",
    ]
    .map(String::from)
    .to_vec();
    urls.push(format!("ws://{}", onion(55, 'a')));
    urls.push(format!("ws://{}.onion", "a".repeat(55) + "1"));
    urls.push(format!("ws://{}", "a".repeat(56)));
    urls.push(format!("ws://{}:80", onion(56, 'a')));
    urls.push(format!("wss://{}", "a".repeat(251)));
    urls
}

/// 513 bytes whose key 0 alone would say `UnsupportedVersion` (R7).
fn oversized() -> Vec<u8> {
    let head = [field(0, &[2]), field(1, &[1])].concat();
    let filler = MAX_RECORD + 1 - head.len() - 5;
    [head, field(9, &vec![0; filler])].concat()
}

/// QR texts R11 rejects, each next to the canonical text it breaks.
fn bad_qr_texts() -> Vec<Vec<u8>> {
    let text = base64url::encode(&encode(&fields())).unwrap();
    assert_eq!(
        text.len() % 4,
        3,
        "the base record needs a padding character"
    );
    // The last character of a two-byte tail carries two bits past the data,
    // both zero; the next character of the alphabet sets one of them.
    let mut last_bit = text.to_vec();
    *last_bit.last_mut().unwrap() += 1;
    let mut plus = text.to_vec();
    plus[0] = b'+';
    let mut slash = text.to_vec();
    slash[0] = b'/';
    vec![
        [text.as_slice(), b"="].concat(),
        plus,
        slash,
        last_bit,
        b"AAAAA".to_vec(),
        vec![b'A'; MAX_QR + 1],
    ]
}

/// Spec 011, R1: the keys of §5, key 6 optional and every other mandatory.
#[test]
fn s011_t01_r01_parses_the_reference_config() {
    let record = encode(&fields());
    let config = Config::parse(&record, NOW).unwrap();
    assert_eq!(config.server_url(), "wss://host");
    assert_eq!(config.ttl_seconds(), 86_400);
    assert_eq!(config.suggested_name(), "name");
    assert_eq!(config.record(None).unwrap().as_slice(), record);
    let invited = with(6, &NOW.to_be_bytes());
    let config = Config::parse(&invited, NOW).unwrap();
    assert_eq!(config.record(Some(NOW)).unwrap().as_slice(), invited);
    for key in [0, 1, 2, 3, 4, 5, 7] {
        assert_eq!(
            rejection(&without(key)),
            Some(Error::BadConfig),
            "key {key}"
        );
    }
}

/// Spec 011, R2: every `RecordError` is `BadConfig`.
#[test]
fn s011_t02_r02_rejects_malformed_records() {
    for (at, record) in malformed().iter().enumerate() {
        assert_eq!(rejection(record), Some(Error::BadConfig), "case {at}");
    }
}

/// Spec 011, R3: the versions are read before anything after key 1.
#[test]
fn s011_t03_r03_version_is_read_first() {
    for (at, record) in unsupported().iter().enumerate() {
        assert_eq!(
            rejection(record),
            Some(Error::UnsupportedVersion),
            "case {at}"
        );
    }
    assert_eq!(rejection(&without(1)), Some(Error::BadConfig));
    assert_eq!(rejection(&with(0, &[1, 1])), Some(Error::BadConfig));
}

/// Spec 011, R4: the TTL and name ranges.
#[test]
fn s011_t04_r04_ttl_and_name_ranges() {
    for (at, record) in out_of_range().iter().enumerate() {
        assert_eq!(rejection(record), Some(Error::BadConfig), "case {at}");
    }
    for record in [
        with(4, &60u32.to_be_bytes()),
        with(4, &2_592_000u32.to_be_bytes()),
        with(7, &[b'a'; 64]),
        with(7, "a\u{200b}b".as_bytes()),
    ] {
        assert!(Config::parse(&record, NOW).is_ok());
    }
}

/// Spec 011, R5: the URL grammar, alone and through `parse` and `create`.
#[test]
fn s011_t05_r05_url_grammar() {
    let good = [
        "wss://host".to_owned(),
        "wss://host:9001".to_owned(),
        "wss://1.2.3.4".to_owned(),
        "wss://host:65535".to_owned(),
        format!("wss://{}", onion(56, '7')),
        format!("wss://{}", "a".repeat(250)),
        format!("ws://{}", onion(56, 'z')),
        format!("ws://{}:9001", onion(56, '2')),
    ];
    for server_url in &good {
        assert!(url::parse(server_url).is_ok(), "{server_url}");
        assert!(Config::parse(&with(3, server_url.as_bytes()), NOW).is_ok());
    }
    assert_eq!(good[5].len(), 256);
    for server_url in bad_urls() {
        assert_eq!(
            url::parse(&server_url).err(),
            Some(Error::BadConfig),
            "{server_url}"
        );
        assert_eq!(
            rejection(&with(3, server_url.as_bytes())),
            Some(Error::BadConfig)
        );
        let created = Config::create(&server_url, 86_400, "name", NOW);
        assert_eq!(created.err(), Some(Error::BadConfig), "{server_url}");
    }
}

/// Spec 011, R6: the accessors, and `host()` without scheme or port.
#[test]
fn s011_t06_r06_accessors_and_host() {
    let config = Config::parse(&with(3, b"wss://host:9001"), NOW).unwrap();
    assert_eq!(config.server_url(), "wss://host:9001");
    assert_eq!(config.host(), "host");
    assert_eq!(config.ttl_seconds(), 86_400);
    assert_eq!(config.suggested_name(), "name");
    assert!(*config.channel_key() == Secret::from_bytes(K_CH));
    let onion_url = format!("ws://{}:9001", onion(56, 'a'));
    let config = Config::parse(&with(3, onion_url.as_bytes()), NOW).unwrap();
    assert_eq!(config.host(), onion(56, 'a'));
    assert_eq!(reference().host(), "host");
}

/// Spec 011, R7: the size is checked before the first byte is decoded.
#[test]
fn s011_t07_r07_rejects_a_record_above_the_limit() {
    let record = oversized();
    assert_eq!(record.len(), 513);
    assert_eq!(rejection(&record), Some(Error::BadConfig));
}

/// Spec 011, R8: the identity is §4's composition of the primitives, and the
/// TTL is part of it. The known answers are the vectors of `011.json`.
#[test]
fn s011_t08_r08_channel_id_known_answer() {
    let config = reference();
    let seed = crypto::kdf_derive(&Secret::copy_from(&K_CH), &CHANNEL_AUTH_CONTEXT).unwrap();
    let (pk_ch, _) = crypto::sign_keypair_from_seed(&seed).unwrap();
    let digest = crypto::hash(&[&CHANNEL_ID_TAG[..], &pk_ch.0, &86_400u32.to_be_bytes()].concat());
    assert_eq!(config.channel_id(), digest.unwrap()[..16]);
    assert!(ct_eq(&config.id().0, &config.channel_id()));
    assert!(ct_eq(&config.channel_keypair().unwrap().0.0, &pk_ch.0));
    let other = Config::from_parts(Secret::copy_from(&K_CH), "wss://host", 86_401, "name", NOW);
    assert!(!ct_eq(&other.unwrap().channel_id(), &config.channel_id()));
}

/// Spec 011, R9: the two literals, as `docs/spec.md` §4 writes them.
#[test]
fn s011_t09_r09_literals_and_lengths() {
    assert_eq!(CHANNEL_ID_TAG, b"privatechat/chid/v1");
    assert_eq!(CHANNEL_ID_TAG.len(), 19);
    assert_eq!(format!("{CHANNEL_AUTH_CONTEXT:?}"), "6368617574685f5f"); // "chauth__"
    let spec = include_str!("../../../../../docs/spec.md");
    assert!(spec.contains("| `privatechat/chid/v1` | `channel_id` |"));
    assert!(spec.contains("crypto_sign_seed_keypair(KDF(K_ch, \"chauth__\"))"));
}

/// Spec 011, R10: an expired invitation is refused; one that expires at
/// `now` is accepted and forgotten. `open_encrypted` joins with slice (e).
#[test]
fn s011_t10_r10_expired_invitation_on_every_path() {
    let expired = with(6, &(NOW - 1).to_be_bytes());
    assert_eq!(rejection(&expired), Some(Error::InviteExpired));
    let qr = base64url::encode(&expired).unwrap();
    assert_eq!(Config::parse_qr(&qr, NOW).err(), Some(Error::InviteExpired));
    let qr = reference().export_qr(NOW - 600_000).unwrap();
    let config = Config::parse_qr(&qr, NOW).unwrap();
    assert_eq!(config.record(None).unwrap().as_slice(), encode(&fields()));
    let config = Config::parse(&with(6, &NOW.to_be_bytes()), NOW).unwrap();
    assert_eq!(config.record(None).unwrap().as_slice(), encode(&fields()));
}

/// Spec 011, R11: the QR is the canonical base64url of the record, and
/// nothing else parses.
#[test]
fn s011_t11_r11_qr_is_canonical_base64url() {
    let qr = base64url::encode(&encode(&fields())).unwrap();
    assert!(Config::parse_qr(&qr, NOW).is_ok());
    for (at, text) in bad_qr_texts().iter().enumerate() {
        assert_eq!(
            Config::parse_qr(text, NOW).err(),
            Some(Error::BadConfig),
            "case {at}"
        );
    }
    let largest = base64url::encode(&[0; MAX_RECORD]).unwrap();
    assert_eq!(largest.len(), MAX_QR);
}

proptest! {
    /// Spec 011, R12: decode(encode(x)) = x, and the codec alone rejects
    /// every text R11 rejects.
    #[test]
    fn s011_t12_r12_base64url_round_trip(bytes in bytes_of(any::<u8>(), 0..=MAX_RECORD)) {
        let text = base64url::encode(&bytes).unwrap();
        assert!(text.iter().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(byte)));
        assert_eq!(base64url::decode(&text).unwrap().as_slice(), bytes);
    }
}

#[test]
fn s011_t12_r12_base64url_rejects_alone() {
    let (too_long, rest) = bad_qr_texts()
        .split_last()
        .map(|(l, r)| (l.clone(), r.to_vec()))
        .unwrap();
    assert_eq!(
        too_long.len(),
        MAX_QR + 1,
        "the codec bounds no length: R11 does"
    );
    for (at, text) in rest.iter().enumerate() {
        assert!(base64url::decode(text).is_none(), "case {at}");
    }
    assert_eq!(base64url::encode(b"\xff").unwrap().as_slice(), b"_w");
    assert_eq!(base64url::encode(b"\xfb\xef").unwrap().as_slice(), b"--8");
    assert!(base64url::decode(b"_x").is_none());
}

/// Spec 011, R19: `copy_from` holds the bytes it copied, the codec's outputs
/// are allocated at their exact size, and no secret type was added. The
/// file's buffers join with slice (e).
#[test]
fn s011_t19_r19_no_lingering_secret() {
    for len in 0..=MAX_RECORD {
        let text = base64url::encode(&vec![0x5a; len]).unwrap();
        assert_eq!(text.capacity(), text.len(), "encode {len}");
        let bytes = base64url::decode(&text).unwrap();
        assert_eq!(bytes.capacity(), len, "decode {len}");
    }
    assert!(Secret::copy_from(&K_CH) == Secret::from_bytes(K_CH));
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>"]);
}

/// Spec 011, R21: no rejection carries a byte of `K_ch`.
#[test]
fn s011_t21_r21_a_rejected_config_leaves_nothing() {
    let urls = bad_urls()
        .iter()
        .map(|url| with(3, url.as_bytes()))
        .collect();
    let records = [malformed(), unsupported(), out_of_range(), urls].concat();
    let expired = with(6, &(NOW - 1).to_be_bytes());
    for record in records.iter().chain([&oversized(), &expired]) {
        let debug = format!("{:?}", rejection(record).unwrap());
        assert!(
            debug.bytes().all(|byte| byte.is_ascii_alphabetic()),
            "{debug}"
        );
    }
}

/// Spec 011, R23: `create` draws `K_ch` and checks its inputs.
#[test]
fn s011_t23_r23_create() {
    let one = Config::create("wss://host", 86_400, "name", NOW).unwrap();
    let two = Config::create("wss://host", 86_400, "name", NOW).unwrap();
    assert!(one.k_ch != two.k_ch);
    assert!(!ct_eq(&one.channel_id(), &two.channel_id()));
    for config in [&one, &two] {
        assert_eq!(config.server_url(), "wss://host");
        assert_eq!(config.ttl_seconds(), 86_400);
        assert_eq!(config.suggested_name(), "name");
        assert_eq!(config.created_at, NOW);
        let record = config.record(None).unwrap();
        let with_k_ch = with(2, config.k_ch.expose());
        assert_eq!(record.as_slice(), with_k_ch, "no key 6");
    }
    let long_name = "a".repeat(65);
    for (server_url, ttl, name) in [
        ("wss://host", 59, "name"),
        ("wss://host", 86_400, long_name.as_str()),
        ("ws://host", 86_400, "name"),
    ] {
        let created = Config::create(server_url, ttl, name, NOW);
        assert_eq!(created.err(), Some(Error::BadConfig));
    }
}

fn check_positive(vector: &Vector) {
    let name = vector.name();
    let record = vector.input("record").bytes();
    let config = Config::parse(record, vector.input("now").u64_hex()).expect(name);
    let text = |field| core::str::from_utf8(vector.expected(field).bytes()).unwrap();
    assert_eq!(config.server_url(), text("server_url"), "{name}");
    assert_eq!(config.suggested_name(), text("suggested_name"), "{name}");
    assert_eq!(
        config.ttl_seconds(),
        vector.expected("ttl_seconds").number()
    );
    assert_eq!(
        config.k_ch.expose(),
        &vector.expected("k_ch").array(),
        "{name}"
    );
    let pk_ch = config.channel_keypair().unwrap().0;
    assert_eq!(pk_ch.0, vector.expected("pk_ch").array(), "{name}");
    assert_eq!(
        config.channel_id(),
        vector.expected("channel_id").array(),
        "{name}"
    );
    let expiry = vector
        .has_expected("invite_expires_at")
        .then(|| vector.expected("invite_expires_at").u64_hex());
    assert_eq!(config.record(expiry).unwrap().as_slice(), record, "{name}");
    if vector.has_expected("qr") {
        let qr = vector.expected("qr").bytes();
        let created_at = vector.expected("created_at").u64_hex();
        assert_eq!(config.export_qr(created_at).unwrap(), qr, "{name}");
        let scanned = Config::parse_qr(qr, vector.input("now").u64_hex()).expect(name);
        assert_eq!(scanned.record(expiry).unwrap().as_slice(), record, "{name}");
    }
}

fn check_negative_qr(vector: &Vector) {
    let name = vector.name();
    let qr = vector.input("qr").bytes();
    let error = Config::parse_qr(qr, vector.input("now").u64_hex()).err();
    let error = format!("{:?}", error.expect(name));
    assert_eq!(error, vector.expected("error").text(), "{name}");
}

fn check_negative(vector: &Vector) {
    let name = vector.name();
    assert_eq!(vector.kind(), Kind::Negative);
    let record = vector.input("record").bytes();
    let error = Config::parse(record, vector.input("now").u64_hex()).err();
    let error = format!("{:?}", error.expect(name));
    assert_eq!(error, vector.expected("error").text(), "{name}");
}

/// Spec 015, R3: every vector of `011.json` is checked once.
#[test]
fn s011_vectors_dispatch() {
    let positive = [
        "config_reference",
        "config_no_invite",
        "config_onion_ws",
        "channel_id_ttl_60",
        "channel_id_ttl_2592000",
    ];
    let negative = [
        "record_key_order",
        "record_unknown_key",
        "record_extra_byte",
        "record_kch_31_bytes",
        "record_version_2",
        "record_proto_version_2",
        "record_513_bytes",
        "ttl_59",
        "ttl_2592001",
        "name_65_bytes",
        "name_control",
        "url_path",
        "url_uppercase",
        "url_port_443",
        "url_ws_not_onion",
        "url_ws_onion_port_80",
        "invite_expired",
    ];
    let qr = ["qr_padding", "qr_nonzero_bits", "qr_length_mod_4"];
    let entries = [
        positive
            .map(|name| (name, check_positive as Checker))
            .as_slice(),
        negative
            .map(|name| (name, check_negative as Checker))
            .as_slice(),
        qr.map(|name| (name, check_negative_qr as Checker))
            .as_slice(),
    ]
    .concat();
    vectors::check_all("011", &entries);
}
