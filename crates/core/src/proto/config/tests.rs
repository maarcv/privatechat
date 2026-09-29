use super::{CHANNEL_AUTH_CONTEXT, CHANNEL_ID_TAG, Config, MAX_RECORD};
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

/// 513 bytes whose key 0 alone would say `UnsupportedVersion` (R7).
fn oversized() -> Vec<u8> {
    let head = [field(0, &[2]), field(1, &[1])].concat();
    let filler = MAX_RECORD + 1 - head.len() - 5;
    [head, field(9, &vec![0; filler])].concat()
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
/// `now` is accepted and forgotten. `parse_qr` and `open_encrypted` join
/// with slices (d) and (e).
#[test]
fn s011_t10_r10_expired_invitation_on_every_path() {
    let expired = with(6, &(NOW - 1).to_be_bytes());
    assert_eq!(rejection(&expired), Some(Error::InviteExpired));
    let config = Config::parse(&with(6, &NOW.to_be_bytes()), NOW).unwrap();
    assert_eq!(config.record(None).unwrap().as_slice(), encode(&fields()));
}

/// Spec 011, R19: `copy_from` holds the bytes it copied, and no secret type
/// was added. The buffer capacities join with slices (d) and (e).
#[test]
fn s011_t19_r19_no_lingering_secret() {
    assert!(Secret::copy_from(&K_CH) == Secret::from_bytes(K_CH));
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>"]);
}

/// Spec 011, R21: no rejection carries a byte of `K_ch`.
#[test]
fn s011_t21_r21_a_rejected_config_leaves_nothing() {
    let records = [malformed(), unsupported(), out_of_range()].concat();
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
    for (ttl, name) in [(59, "name"), (86_400, &"a".repeat(65))] {
        let created = Config::create("wss://host", ttl, name, NOW);
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
        "invite_expired",
    ];
    let entries = [
        positive
            .map(|name| (name, check_positive as Checker))
            .as_slice(),
        negative
            .map(|name| (name, check_negative as Checker))
            .as_slice(),
    ]
    .concat();
    vectors::check_all("011", &entries);
}
