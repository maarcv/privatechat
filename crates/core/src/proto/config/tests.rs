//! Tests of spec 011 over records, QR texts and files built by hand, so that
//! each one breaks exactly the rule it names, and the dispatch of `011.json`.

use proptest::collection::vec as bytes_of;
use proptest::option::of as maybe;
use proptest::prelude::{any, prop_oneof, proptest};
use proptest::strategy::Strategy;

use super::{
    CHANNEL_AUTH_CONTEXT, CHANNEL_ID_TAG, Config, FILE_LEN, FILE_PAD_BLOCK, MAX_QR, MAX_RECORD,
    NONCE_RANGE, SALT_RANGE, SEALED_AT, canonical_password, draw_password, parse_file_header,
    password_of, url, wordlist,
};
use crate::Error;
use crate::crypto::{self, Nonce, SECRET_TYPES, Salt, Secret, TAG_LEN, ct_eq};
use crate::vectors::{self, Checker, Kind, Vector};

const K_CH: [u8; 32] = [0xa5; 32];
const NOW: u64 = 1_790_000_060_000;
const PASSWORD: &[u8] = b"able about above";
const SALT: Salt = Salt([0x11; 16]);
const NONCE: Nonce = Nonce([0x22; 24]);

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

/// The record of `(key, value)` pairs, in the order given.
fn record_of(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
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
    record_of(&edited)
}

fn without(key: u8) -> Vec<u8> {
    let kept: Vec<_> = fields().into_iter().filter(|(k, _)| *k != key).collect();
    record_of(&kept)
}

fn rejection(record: &[u8]) -> Option<Error> {
    Config::parse(record, NOW).err()
}

/// The config of `fields()`.
fn reference() -> Config {
    Config::parse(&record_of(&fields()), NOW).unwrap()
}

/// The largest valid config: a URL of 256 bytes and a name of 64.
fn largest() -> Config {
    let server_url = format!("wss://{}", "a".repeat(250));
    let name = "é".repeat(32);
    Config::from_parts(Secret::copy_from(&K_CH), &server_url, 86_400, &name, NOW).unwrap()
}

fn qr_of(record: &[u8]) -> Vec<u8> {
    crypto::base64url_encode(record).unwrap().to_vec()
}

/// Records that break the strict decode of R2.
fn malformed() -> Vec<Vec<u8>> {
    let mut swapped = fields();
    swapped.swap(3, 4);
    let mut repeated = fields();
    repeated.push((7, b"name".to_vec()));
    vec![
        record_of(&swapped),
        record_of(&repeated),
        [record_of(&fields()), field(8, b"x")].concat(),
        without(2),
        with(2, &[0; 31]),
        with(4, &[0, 1, 0]),
        with(7, &[0xff]),
        [record_of(&fields()), vec![0]].concat(),
    ]
}

/// Records whose versions R3 rejects, some with a broken tail after key 1.
fn unsupported() -> Vec<Vec<u8>> {
    let tail =
        |config: u8, proto: u8| [field(0, &[config]), field(1, &[proto]), vec![0xff, 0]].concat();
    vec![
        with(0, &[0]),
        with(0, &[2]),
        with(1, &[2]),
        [with(0, &[2]), field(8, b"x")].concat(),
        [with(1, &[2]), field(8, b"x")].concat(),
        tail(2, 1),
        tail(0, 1),
        tail(1, 2),
    ]
}

/// Records out of the ranges of R4, the ends of both Cc ranges included.
fn out_of_range() -> Vec<Vec<u8>> {
    let mut records = vec![
        with(4, &59u32.to_be_bytes()),
        with(4, &2_592_001u32.to_be_bytes()),
        with(7, &[b'a'; 65]),
    ];
    for control in ['\u{0}', '\u{1f}', '\u{7f}', '\u{85}', '\u{9f}'] {
        records.push(with(7, format!("a{control}b").as_bytes()));
    }
    records
}

/// A v3 onion host: `label_len` times `character`, then `.onion`.
fn onion(label_len: usize, character: char) -> String {
    format!("{}.onion", character.to_string().repeat(label_len))
}

/// Server URLs inside the grammar of R5.
fn good_urls() -> Vec<String> {
    vec![
        "wss://host".to_owned(),
        "wss://host:9001".to_owned(),
        "wss://1.2.3.4".to_owned(),
        "wss://chat-1.example.org".to_owned(),
        "wss://host:65535".to_owned(),
        format!("wss://{}", onion(56, '7')),
        format!("wss://{}", "a".repeat(250)),
        format!("ws://{}", onion(56, 'z')),
        format!("ws://{}:9001", onion(56, '2')),
    ]
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
        "wss://host_x",
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
    urls.push(format!("ws://{}.onion", "a".repeat(55) + "8"));
    urls.push(format!("ws://{}", onion(56, 'A')));
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

/// QR texts the codec rejects, each next to the canonical text it breaks.
fn bad_qr_texts() -> Vec<Vec<u8>> {
    let text = qr_of(&record_of(&fields()));
    assert_eq!(
        text.len() % 4,
        3,
        "the base record needs a padding character"
    );
    // The last character of a two-byte tail carries two bits past the data,
    // both zero; the next character of the alphabet sets one of them.
    let mut last_bit = text.clone();
    *last_bit.last_mut().unwrap() += 1;
    let mut plus = text.clone();
    plus[0] = b'+';
    let mut slash = text.clone();
    slash[0] = b'/';
    vec![
        [text.as_slice(), b"="].concat(),
        plus,
        slash,
        last_bit,
        b"AAAAA".to_vec(),
    ]
}

/// The key of the files whose tests do not need Argon2id.
fn file_key() -> Secret<32> {
    Secret::from_bytes([0x33; 32])
}

/// A file of the reference config under `file_key()`.
fn keyed_file() -> Vec<u8> {
    let file = reference().seal_file_with_key(&file_key(), &SALT, &NONCE, NOW);
    file.unwrap()
}

/// A file whose box holds `content` under `file_key()`, built by hand.
fn file_around(content: &[u8]) -> Vec<u8> {
    let sealed = crypto::secretbox_seal(&file_key(), &NONCE, content).unwrap();
    [&b"PCFG\x01"[..], &SALT.0, &NONCE.0, &sealed].concat()
}

/// Headers R13 rejects, with the error of the first check each one fails.
fn bad_headers() -> Vec<(Vec<u8>, Error)> {
    let file = keyed_file();
    let mut magic = file.clone();
    magic[0] ^= 1;
    let mut version = file.clone();
    version[4] = 2;
    let mut magic_and_version = magic.clone();
    magic_and_version[4] = 2;
    vec![
        (file[..4].to_vec(), Error::BadConfig),
        (magic, Error::BadConfig),
        (magic_and_version, Error::BadConfig),
        (file[..FILE_LEN - 1].to_vec(), Error::BadConfig),
        ([file.as_slice(), &[0]].concat(), Error::BadConfig),
        (version.clone(), Error::UnsupportedVersion),
        (version[..FILE_LEN - 1].to_vec(), Error::UnsupportedVersion),
        (version[..100].to_vec(), Error::UnsupportedVersion),
        (b"PCFG\x02".to_vec(), Error::UnsupportedVersion),
    ]
}

/// Typed passwords R15 rejects before any key is derived.
fn bad_passwords() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b" \t ".to_vec(),
        vec![0xff],
        vec![b'a'; 1_025],
        [&b"able"[..], &[b' '; 1_021]].concat(),
        vec![b'a'; 257],
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Spec 011, R1: the keys of §5, key 6 optional and every other mandatory.
#[test]
fn s011_t01_r01_parses_the_reference_config() {
    let record = record_of(&fields());
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

/// Spec 011, R3: the versions are read after key 1 and before anything else;
/// a failure before that point is `BadConfig`.
#[test]
fn s011_t03_r03_version_is_read_first() {
    for (at, record) in unsupported().iter().enumerate() {
        assert_eq!(
            rejection(record),
            Some(Error::UnsupportedVersion),
            "case {at}"
        );
    }
    for record in [
        without(1),
        with(0, &[1, 1]),
        field(0, &[2]),
        [field(0, &[2]), field(1, &[1, 1])].concat(),
    ] {
        assert_eq!(rejection(&record), Some(Error::BadConfig));
    }
}

/// Spec 011, R4: the TTL and name ranges, checked before the expiry (R3).
#[test]
fn s011_t04_r04_ttl_and_name_ranges() {
    for (at, record) in out_of_range().iter().enumerate() {
        assert_eq!(rejection(record), Some(Error::BadConfig), "case {at}");
    }
    for record in [
        with(4, &60u32.to_be_bytes()),
        with(4, &2_592_000u32.to_be_bytes()),
        with(7, &[b'a'; 64]),
        with(7, "é".repeat(32).as_bytes()),
        with(7, "a\u{200b}\u{a0}b".as_bytes()),
    ] {
        assert!(Config::parse(&record, NOW).is_ok());
    }
    let mut expired = fields();
    expired[4].1 = 59u32.to_be_bytes().to_vec();
    expired.insert(6, (6, (NOW - 1).to_be_bytes().to_vec()));
    assert_eq!(rejection(&record_of(&expired)), Some(Error::BadConfig));
}

/// Spec 011, R5: the URL grammar, alone and through `parse` and `create`.
#[test]
fn s011_t05_r05_url_grammar() {
    let good = good_urls();
    assert_eq!(good[6].len(), 256);
    for server_url in &good {
        assert!(url::parse(server_url).is_ok(), "{server_url}");
        assert!(Config::parse(&with(3, server_url.as_bytes()), NOW).is_ok());
    }
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
/// TTL is part of it. The known answers are `config_reference` and the
/// `channel_id_ttl_*` vectors, checked by `s011_vectors_dispatch`.
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
/// `now` is accepted and forgotten, on each of the three paths.
#[test]
fn s011_t10_r10_expired_invitation_on_every_path() {
    let expired = with(6, &(NOW - 1).to_be_bytes());
    assert_eq!(rejection(&expired), Some(Error::InviteExpired));
    assert_eq!(
        Config::parse_qr(&qr_of(&expired), NOW).err(),
        Some(Error::InviteExpired)
    );
    let file = reference().seal_file(PASSWORD, &SALT, &NONCE, NOW).unwrap();
    let late = NOW + 86_400_001;
    let opened = Config::open_encrypted(&file, PASSWORD, late);
    assert_eq!(opened.err(), Some(Error::InviteExpired));
    let opened = Config::open_encrypted(&file, PASSWORD, late - 1).unwrap();
    assert_eq!(
        opened.record(None).unwrap().as_slice(),
        record_of(&fields())
    );
    let qr = reference().export_qr(NOW - 600_000).unwrap();
    let config = Config::parse_qr(&qr, NOW).unwrap();
    assert_eq!(
        config.record(None).unwrap().as_slice(),
        record_of(&fields())
    );
    let config = Config::parse(&with(6, &NOW.to_be_bytes()), NOW).unwrap();
    assert_eq!(
        config.record(None).unwrap().as_slice(),
        record_of(&fields())
    );
}

/// Spec 011, R11: the QR is the canonical base64url of the record, bounded
/// before it is decoded, and nothing else parses.
#[test]
fn s011_t11_r11_qr_is_canonical_base64url() {
    assert!(Config::parse_qr(&qr_of(&record_of(&fields())), NOW).is_ok());
    for (at, text) in bad_qr_texts().iter().enumerate() {
        assert_eq!(
            Config::parse_qr(text, NOW).err(),
            Some(Error::BadConfig),
            "case {at}"
        );
    }
    assert_eq!(
        Config::parse_qr(&[b'A'; MAX_QR + 1], NOW).err(),
        Some(Error::BadConfig)
    );
    // The largest text decodes: a 512-byte record whose version says
    // `UnsupportedVersion` proves it reached R3.
    let head = [field(0, &[2]), field(1, &[1])].concat();
    let record = [
        head.clone(),
        field(9, &vec![0; MAX_RECORD - head.len() - 5]),
    ]
    .concat();
    let largest = qr_of(&record);
    assert_eq!(largest.len(), MAX_QR);
    assert_eq!(
        Config::parse_qr(&largest, NOW).err(),
        Some(Error::UnsupportedVersion)
    );
}

proptest! {
    /// Spec 011, R12: the codec gives back what it encodes.
    #[test]
    fn s011_t12_r12_base64url_round_trip(bytes in bytes_of(any::<u8>(), 0..=MAX_RECORD)) {
        let text = crypto::base64url_encode(&bytes).unwrap();
        assert_eq!(crypto::base64url_decode(&text).unwrap().as_slice(), bytes.as_slice());
    }
}

/// Spec 011, R12: the codec alone rejects every text R11 rejects but the
/// length bound, which `parse_qr` applies.
#[test]
fn s011_t12_r12_base64url_rejects_alone() {
    for (at, text) in bad_qr_texts().iter().enumerate() {
        let decoded = crypto::base64url_decode(text);
        assert_eq!(
            decoded.err(),
            Some(crypto::CryptoError::BadEncoding),
            "case {at}"
        );
    }
}

/// Spec 011, R13: the header in its order, before the password and the key;
/// then the box, the padding and the record by R3.
#[test]
fn s011_t13_r13_file_order() {
    assert_eq!(SEALED_AT + TAG_LEN + FILE_PAD_BLOCK, FILE_LEN);
    let file = keyed_file();
    assert_eq!(file.len(), FILE_LEN);
    assert_eq!(parse_file_header(&file), Ok(()));
    for (at, (bytes, error)) in bad_headers().iter().enumerate() {
        assert_eq!(parse_file_header(bytes), Err(*error), "case {at}");
    }
    let opened = Config::open_encrypted(&file[..4], &[b'a'; 1_025], NOW);
    assert_eq!(opened.err(), Some(Error::BadConfig));
    let unpadded = file_around(&[0; FILE_PAD_BLOCK]);
    let opened = Config::open_file_with_key(&unpadded, &file_key(), NOW);
    assert_eq!(opened.err(), Some(Error::BadConfig));
    let mut version_2 = with(0, &[2]);
    crypto::pad(&mut version_2, FILE_PAD_BLOCK).unwrap();
    let opened = Config::open_file_with_key(&file_around(&version_2), &file_key(), NOW);
    assert_eq!(opened.err(), Some(Error::UnsupportedVersion));
}

/// Spec 011, R14: a wrong password and a corrupted file are one error.
#[test]
fn s011_t14_r14_wrong_password_and_corruption_are_one_error() {
    let file = reference().seal_file(PASSWORD, &SALT, &NONCE, NOW).unwrap();
    let opened = Config::open_encrypted(&file, b"able about absent", NOW);
    assert_eq!(opened.err(), Some(Error::BadPassword));
    let regions = [
        SALT_RANGE.start,
        SALT_RANGE.end - 1,
        NONCE_RANGE.start,
        NONCE_RANGE.end - 1,
        SEALED_AT,
        SEALED_AT + TAG_LEN,
        FILE_LEN - 1,
    ];
    for at in regions {
        let mut corrupted = file.clone();
        corrupted[at] ^= 0x80;
        let opened = Config::open_encrypted(&corrupted, PASSWORD, NOW);
        assert_eq!(opened.err(), Some(Error::BadPassword), "byte {at}");
    }
}

/// Spec 011, R15: the typed password is bounded, then canonicalised.
#[test]
fn s011_t15_r15_password_canonical_form() {
    let file = reference().seal_file(PASSWORD, &SALT, &NONCE, NOW).unwrap();
    let typed = " Able\tABOUT\u{a0}\u{3000}above ";
    assert!(Config::open_encrypted(&file, typed.as_bytes(), NOW).is_ok());
    for (at, typed) in bad_passwords().iter().enumerate() {
        let opened = Config::open_encrypted(&file, typed, NOW);
        assert_eq!(opened.err(), Some(Error::BadPassword), "case {at}");
        assert_eq!(
            canonical_password(typed).err(),
            Some(Error::BadPassword),
            "case {at}"
        );
    }
    assert!(canonical_password(&[b'a'; 256]).is_ok());
    let spaced = [&b"able"[..], &[b' '; 1_020]].concat();
    assert_eq!(canonical_password(&spaced).unwrap().as_slice(), b"able");
}

/// Typed passwords for the canonical form: any UTF-8 of up to 256
/// characters, ASCII of up to 1 024 bytes, and any bytes.
fn typed_passwords() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        "(?s).{0,256}".prop_map(String::into_bytes),
        "[ a-zA-Z\t]{0,1024}".prop_map(String::into_bytes),
        bytes_of(any::<u8>(), 0..=1_024),
    ]
}

proptest! {
    /// Spec 011, R15: canonicalising is idempotent, leaves no uppercase ASCII
    /// letter and no whitespace but single inner spaces, and never outgrows
    /// the typed length (R19).
    #[test]
    fn s011_t15_r15_canonical_form_is_stable(typed in typed_passwords()) {
        if let Ok(canonical) = canonical_password(&typed) {
            assert_eq!(canonical.capacity(), typed.len());
            assert_eq!(canonical_password(&canonical).unwrap().as_slice(), canonical.as_slice());
            let text = core::str::from_utf8(&canonical).unwrap();
            assert!(!text.bytes().any(|byte| byte.is_ascii_uppercase()));
            assert!(!text.starts_with(' ') && !text.ends_with(' ') && !text.contains("  "));
            assert!(text.chars().all(|c| c == ' ' || !c.is_whitespace()));
        }
    }
}

/// Spec 011, R16: the export draws 7 list words that open its file, under a
/// fresh salt and nonce; each index is the low 11 bits of a big-endian pair.
#[test]
fn s011_t16_r16_export_draws_the_password() {
    let config = reference();
    let (file, password) = config.export_encrypted(NOW).unwrap();
    let text = core::str::from_utf8(&password).unwrap();
    let words: Vec<&str> = text.split(' ').collect();
    assert_eq!(words.len(), 7);
    assert!(
        words
            .iter()
            .all(|word| wordlist::WORDS.lines().any(|listed| listed == *word))
    );
    assert!(password.len() <= 62);
    assert_eq!(
        canonical_password(&password).unwrap().as_slice(),
        password.as_slice()
    );
    assert!(Config::open_encrypted(&file, &password, NOW).is_ok());
    let (other_file, other_password) = config.export_encrypted(NOW).unwrap();
    assert!(other_password != password);
    assert_ne!(file[SALT_RANGE], other_file[SALT_RANGE]);
    assert_ne!(file[NONCE_RANGE], other_file[NONCE_RANGE]);
    for bit in 0..11 {
        let index = 1u16 << bit;
        let mut draws = [0u8; 14];
        draws[..2].copy_from_slice(&(index | 0xf800).to_be_bytes());
        let drawn = password_of(&draws).unwrap();
        let expected = [wordlist::word(index).unwrap(); 1]
            .into_iter()
            .chain([wordlist::word(0).unwrap(); 6])
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(core::str::from_utf8(&drawn).unwrap(), expected, "bit {bit}");
    }
}

/// Spec 011, R17: the list is the English BIP-39 list, pinned by its digest.
#[test]
fn s011_t17_r17_word_list_is_pinned() {
    let words: Vec<&str> = wordlist::WORDS.lines().collect();
    assert_eq!(words.len(), usize::from(wordlist::WORD_COUNT));
    assert!(
        words.windows(2).all(|pair| pair[0] < pair[1]),
        "sorted and unique"
    );
    assert!(wordlist::WORDS.ends_with('\n') && !wordlist::WORDS.contains('\r'));
    let digest = crypto::hash(wordlist::WORDS.as_bytes()).unwrap();
    assert_eq!(
        hex(&digest),
        "6fefd6b6e47ee66e6bbf8ee322305deebeefb1bd9b24e8618bf126d870175bb7"
    );
    assert_eq!(wordlist::word(0), Some("abandon"));
    assert_eq!(wordlist::word(2_047), Some("zoo"));
    assert_eq!(wordlist::word(2_048), None);
}

/// Spec 011, R18: each form writes its fixed expiry, and one that does not
/// fit is `Internal`. The checker of `chatcfg_reference` in
/// `s011_vectors_dispatch` compares `seal_file` with the pinned bytes.
#[test]
fn s011_t18_r18_fixed_invitation_expiry() {
    let config = reference();
    let qr = crypto::base64url_decode(&config.export_qr(NOW).unwrap()).unwrap();
    assert_eq!(
        qr.as_slice(),
        config.record(Some(NOW + 600_000)).unwrap().as_slice()
    );
    let mut padded = config.record(Some(NOW + 86_400_000)).unwrap().to_vec();
    crypto::pad(&mut padded, FILE_PAD_BLOCK).unwrap();
    assert_eq!(config.padded_record(NOW).unwrap().as_slice(), padded);
    let file = keyed_file();
    assert!(Config::open_file_with_key(&file, &file_key(), NOW + 86_400_000).is_ok());
    assert!(config.export_qr(u64::MAX - 600_000).is_ok());
    assert_eq!(
        config.export_qr(u64::MAX - 599_999).err(),
        Some(Error::Internal)
    );
    let sealed = config.seal_file_with_key(&file_key(), &SALT, &NONCE, u64::MAX - 86_399_999);
    assert_eq!(sealed.err(), Some(Error::Internal));
    assert_eq!(
        config.export_encrypted(u64::MAX).err(),
        Some(Error::Internal)
    );
}

/// Spec 011, R19: `copy_from` holds the bytes it copied; the codec's outputs,
/// the padded record, the drawn password and the canonical password are
/// allocated once, at their size; and no secret type was added.
#[test]
fn s011_t19_r19_no_lingering_secret() {
    for len in 0..=MAX_RECORD {
        let text = crypto::base64url_encode(&vec![0x5a; len]).unwrap();
        assert_eq!(
            text.capacity(),
            text.len() + 1,
            "encode {len}: text and terminator"
        );
        let bytes = crypto::base64url_decode(&text).unwrap();
        assert_eq!(bytes.capacity(), len, "decode {len}");
    }
    let padded = reference().padded_record(NOW).unwrap();
    assert_eq!(
        (padded.len(), padded.capacity()),
        (FILE_PAD_BLOCK, FILE_PAD_BLOCK)
    );
    assert_eq!(draw_password().unwrap().capacity(), 62);
    let typed = [
        &b" Able\tABOUT above "[..],
        &[b'a'; 256],
        "\u{3000}x".as_bytes(),
    ];
    for typed in typed {
        assert_eq!(canonical_password(typed).unwrap().capacity(), typed.len());
    }
    assert!(Secret::copy_from(&K_CH) == Secret::from_bytes(K_CH));
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>"]);
}

/// Spec 011, R20: `Forged` from the secret box is `BadPassword`.
#[test]
fn s011_t20_r20_forged_box_is_bad_password() {
    let opened = Config::open_file_with_key(&keyed_file(), &Secret::from_bytes(K_CH), NOW);
    assert_eq!(opened.err(), Some(Error::BadPassword));
}

/// Spec 011, R21: no rejection carries a byte of `K_ch` or of the password:
/// every error is a bare variant name.
#[test]
fn s011_t21_r21_a_rejected_config_leaves_nothing() {
    let urls = bad_urls()
        .iter()
        .map(|url| with(3, url.as_bytes()))
        .collect();
    let records = [malformed(), unsupported(), out_of_range(), urls].concat();
    let expired = with(6, &(NOW - 1).to_be_bytes());
    let mut errors: Vec<Error> = records
        .iter()
        .chain([&oversized(), &expired])
        .map(|record| rejection(record).unwrap())
        .collect();
    let qr = bad_qr_texts();
    errors.extend(
        qr.iter()
            .map(|text| Config::parse_qr(text, NOW).err().unwrap()),
    );
    let file = keyed_file();
    for typed in bad_passwords() {
        errors.push(Config::open_encrypted(&file, &typed, NOW).err().unwrap());
    }
    for (bytes, _) in bad_headers() {
        errors.push(Config::open_encrypted(&bytes, PASSWORD, NOW).err().unwrap());
    }
    let wrong_key = Config::open_file_with_key(&file, &Secret::from_bytes(K_CH), NOW);
    errors.push(wrong_key.err().unwrap());
    errors.push(Config::create("ws://host", 59, "name", NOW).err().unwrap());
    errors.push(reference().export_qr(u64::MAX).err().unwrap());
    for error in errors {
        let debug = format!("{error:?}");
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
        assert_eq!(record.as_slice(), with(2, config.k_ch.expose()), "no key 6");
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

/// The three forms of R24 give back `config`'s record.
fn assert_round_trips(config: &Config, now: u64) {
    let record = config.record(None).unwrap();
    let parsed = Config::parse(&record, now).unwrap();
    assert_eq!(parsed.record(None).unwrap().as_slice(), record.as_slice());
    let scanned = Config::parse_qr(&config.export_qr(now).unwrap(), now).unwrap();
    assert_eq!(scanned.record(None).unwrap().as_slice(), record.as_slice());
    let file = config
        .seal_file_with_key(&file_key(), &SALT, &NONCE, now)
        .unwrap();
    let opened = Config::open_file_with_key(&file, &file_key(), now).unwrap();
    assert_eq!(opened.record(None).unwrap().as_slice(), record.as_slice());
}

/// Spec 011, R24: the largest valid config, 414 bytes with key 6, goes
/// through all three forms.
#[test]
fn s011_t24_r24_round_trips_the_largest_config() {
    let config = largest();
    assert_eq!(config.record(Some(NOW)).unwrap().len(), 414);
    assert_round_trips(&config, NOW);
}

/// Any URL of the grammar of R5: a TLS host up to the URL bound, or an onion
/// host, each with any port but the one its scheme implies.
fn server_urls() -> impl Strategy<Value = String> {
    let tls = ("[a-z0-9.-]{1,244}", maybe(1u16..=65_535))
        .prop_filter("no implied port", |(_, port)| *port != Some(443))
        .prop_map(|(host, port)| with_port(format!("wss://{host}"), port));
    let onion = ("[a-z2-7]{56}", maybe(1u16..=65_535))
        .prop_filter("no implied port", |(_, port)| *port != Some(80))
        .prop_map(|(label, port)| with_port(format!("ws://{label}.onion"), port));
    prop_oneof![tls, onion]
}

fn with_port(url: String, port: Option<u16>) -> String {
    port.map_or(url.clone(), |port| format!("{url}:{port}"))
}

/// Any name of 0..=64 bytes without Cc: ASCII up to the bound, or any
/// characters up to 16.
fn names() -> impl Strategy<Value = String> {
    prop_oneof!["[ -~]{0,64}", "[^\\p{Cc}]{0,16}"]
}

proptest! {
    /// Spec 011, R24: the record, the QR and the file each give back the
    /// config they encode.
    #[test]
    fn s011_t24_r24_round_trips(
        k_ch in any::<[u8; 32]>(),
        server_url in server_urls(),
        ttl_seconds in 60u32..=2_592_000,
        name in names(),
        created_at in 0u64..=u64::MAX / 2,
    ) {
        assert!(url::parse(&server_url).is_ok(), "{server_url}");
        let k_ch = Secret::copy_from(&k_ch);
        let config = Config::from_parts(k_ch, &server_url, ttl_seconds, &name, created_at);
        assert_round_trips(&config.unwrap(), created_at);
    }
}

fn check_positive(vector: &Vector) {
    let name = vector.name();
    let record = vector.input("record").bytes();
    let now = vector.input("now").u64_hex();
    let config = Config::parse(record, now).expect(name);
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
    let built = Config::from_parts(
        Secret::copy_from(&vector.expected("k_ch").array()),
        text("server_url"),
        vector.expected("ttl_seconds").number(),
        text("suggested_name"),
        vector.expected("created_at").u64_hex(),
    );
    assert_eq!(
        built.unwrap().record(expiry).unwrap().as_slice(),
        record,
        "{name}"
    );
    let qr = vector.input("qr").bytes();
    let scanned = Config::parse_qr(qr, now).expect(name);
    assert_eq!(scanned.record(expiry).unwrap().as_slice(), record, "{name}");
    if expiry.is_some() {
        // `config_reference`: exported at its creation, the QR carries the
        // fixed 10-minute expiry of R18.
        let exported = config
            .export_qr(vector.expected("created_at").u64_hex())
            .unwrap();
        assert_eq!(exported, qr, "{name}: export_qr writes the fixed expiry");
    }
}

/// Every negative: each form it carries (record, QR text, file with a typed
/// password) gives its error.
fn check_negative(vector: &Vector) {
    let name = vector.name();
    assert_eq!(vector.kind(), Kind::Negative);
    let now = vector.input("now").u64_hex();
    let mut errors = Vec::new();
    if vector.has_input("record") {
        errors.push(Config::parse(vector.input("record").bytes(), now).err());
    }
    if vector.has_input("qr") {
        errors.push(Config::parse_qr(vector.input("qr").bytes(), now).err());
    }
    if vector.has_input("file") {
        let password = vector.input("password").bytes();
        errors.push(Config::open_encrypted(vector.input("file").bytes(), password, now).err());
        if vector.has_expected("canonical") {
            let canonical = canonical_password(password).unwrap();
            assert_eq!(
                canonical.as_slice(),
                vector.expected("canonical").bytes(),
                "{name}"
            );
        }
    }
    assert!(!errors.is_empty(), "{name}: no form to check");
    for error in errors {
        let error = format!("{:?}", error.expect(name));
        assert_eq!(error, vector.expected("error").text(), "{name}");
    }
}

/// The pinned file: `seal_file` of the vector's inputs gives its bytes, and
/// they open to the record with the 24-hour expiry (R18, R22). Compared as
/// hexadecimal so that a stale literal fails with the value to paste into
/// the script.
fn check_chatcfg(vector: &Vector) {
    let now = vector.input("now").u64_hex();
    let config = Config::parse(vector.input("record").bytes(), now).unwrap();
    let password = vector.input("password").bytes();
    let salt = Salt(vector.input("salt").array());
    let nonce = Nonce(vector.input("nonce").array());
    let file = config.seal_file(password, &salt, &nonce, now).unwrap();
    assert_eq!(
        hex(&file),
        hex(vector.expected("file").bytes()),
        "{}",
        vector.name()
    );
    let opened = Config::open_encrypted(&file, password, now).unwrap();
    let record = opened.record(Some(now + 86_400_000)).unwrap();
    assert_eq!(record.as_slice(), vector.expected("opened_record").bytes());
}

/// A typed password R15 canonicalises to the file's own.
fn check_password_canonical(vector: &Vector) {
    let now = vector.input("now").u64_hex();
    let typed = vector.input("password").bytes();
    let canonical = canonical_password(typed).unwrap();
    assert_eq!(canonical.as_slice(), vector.expected("canonical").bytes());
    let opened = Config::open_encrypted(vector.input("file").bytes(), typed, now).unwrap();
    let record = opened.record(Some(now + 86_400_000)).unwrap();
    assert_eq!(record.as_slice(), vector.expected("opened_record").bytes());
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
        "record_repeated_key",
        "record_unknown_key",
        "record_missing_key",
        "record_missing_key_1",
        "record_extra_byte",
        "record_kch_31_bytes",
        "record_non_utf8",
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
        "qr_padding",
        "qr_nonzero_bits",
        "qr_length_mod_4",
        "qr_plus",
        "qr_slash",
        "qr_684_bytes",
        "mutate_magic",
        "mutate_version",
        "mutate_salt",
        "mutate_nonce",
        "mutate_sealed",
        "file_4_bytes",
        "file_1084_bytes",
        "file_1086_bytes",
        "password_too_long",
        "password_empty",
        "password_not_utf8",
        "password_canonical_257",
        "password_not_whitespace",
    ];
    let entries = [
        positive
            .map(|name| (name, check_positive as Checker))
            .as_slice(),
        negative
            .map(|name| (name, check_negative as Checker))
            .as_slice(),
        &[
            ("chatcfg_reference", check_chatcfg as Checker),
            ("password_canonical", check_password_canonical as Checker),
        ],
    ]
    .concat();
    vectors::check_all("011", &entries);
}
