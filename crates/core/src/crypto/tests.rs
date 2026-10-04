//! Tests of spec 010: the invariants of the module itself (confinement of
//! `unsafe`, initialisation, secrets, randomness, redacted output), the pins
//! of its build, and every primitive against the vectors of `010.json`.

use proptest::collection::vec as bytes_of;
use proptest::prelude::{any, proptest};
use zeroize::{Zeroize, Zeroizing};

use super::{
    CryptoError, KdfContext, Nonce, PublicKey, SECRET_TYPES, Salt, Secret, Signature, aead_decrypt,
    aead_encrypt, base64url_decode, base64url_encode, check_password_len, checked_output_len,
    ct_eq, ffi, hash, init, init_calls, kdf_derive, keyed_hash, pad, password_key, random_bytes,
    secretbox_open, secretbox_seal, sign_detached, sign_keypair, sign_keypair_from_seed,
    stream_xor, unpad, verify_detached, version,
};
use crate::vectors::{self, Kind};

/// Every `.rs` file of the crate. `core` does no I/O (AGENTS 10), so the test
/// cannot walk the directory: a new file is added to this list by hand.
const SOURCES: [(&str, &str); 62] = [
    ("lib.rs", include_str!("../lib.rs")),
    ("crypto.rs", include_str!("../crypto.rs")),
    ("crypto/ffi.rs", include_str!("ffi.rs")),
    ("crypto/secret.rs", include_str!("secret.rs")),
    ("crypto/tests.rs", include_str!("tests.rs")),
    ("vectors.rs", include_str!("../vectors.rs")),
    ("vectors/tests.rs", include_str!("../vectors/tests.rs")),
    ("error.rs", include_str!("../error.rs")),
    ("fuzz_entry.rs", include_str!("../fuzz_entry.rs")),
    (
        "fuzz_entry/tests.rs",
        include_str!("../fuzz_entry/tests.rs"),
    ),
    ("error/tests.rs", include_str!("../error/tests.rs")),
    ("proto.rs", include_str!("../proto.rs")),
    ("proto/config.rs", include_str!("../proto/config.rs")),
    (
        "proto/config/url.rs",
        include_str!("../proto/config/url.rs"),
    ),
    (
        "proto/config/tests.rs",
        include_str!("../proto/config/tests.rs"),
    ),
    ("proto/record.rs", include_str!("../proto/record.rs")),
    (
        "proto/record/test_schema.rs",
        include_str!("../proto/record/test_schema.rs"),
    ),
    (
        "proto/record/tests.rs",
        include_str!("../proto/record/tests.rs"),
    ),
    ("proto/wordlist.rs", include_str!("../proto/wordlist.rs")),
    ("proto/keys.rs", include_str!("../proto/keys.rs")),
    (
        "proto/keys/tests.rs",
        include_str!("../proto/keys/tests.rs"),
    ),
    ("proto/header.rs", include_str!("../proto/header.rs")),
    (
        "proto/header/tests.rs",
        include_str!("../proto/header/tests.rs"),
    ),
    ("proto/envelope.rs", include_str!("../proto/envelope.rs")),
    (
        "proto/envelope/tests.rs",
        include_str!("../proto/envelope/tests.rs"),
    ),
    (
        "proto/envelope/text_k1.rs",
        include_str!("../proto/envelope/text_k1.rs"),
    ),
    (
        "proto/fingerprint.rs",
        include_str!("../proto/fingerprint.rs"),
    ),
    (
        "proto/fingerprint/tests.rs",
        include_str!("../proto/fingerprint/tests.rs"),
    ),
    ("storage.rs", include_str!("../storage.rs")),
    ("storage/tests.rs", include_str!("../storage/tests.rs")),
    ("storage/state.rs", include_str!("../storage/state.rs")),
    (
        "storage/state/tests.rs",
        include_str!("../storage/state/tests.rs"),
    ),
    ("storage/log.rs", include_str!("../storage/log.rs")),
    (
        "storage/log/tests.rs",
        include_str!("../storage/log/tests.rs"),
    ),
    (
        "storage/settings.rs",
        include_str!("../storage/settings.rs"),
    ),
    (
        "storage/settings/tests.rs",
        include_str!("../storage/settings/tests.rs"),
    ),
    (
        "storage/state/items.rs",
        include_str!("../storage/state/items.rs"),
    ),
    ("testing.rs", include_str!("../testing.rs")),
    (
        "testing/builders.rs",
        include_str!("../testing/builders.rs"),
    ),
    ("testing/compare.rs", include_str!("../testing/compare.rs")),
    ("testing/faults.rs", include_str!("../testing/faults.rs")),
    ("testing/memory.rs", include_str!("../testing/memory.rs")),
    ("testing/tests.rs", include_str!("../testing/tests.rs")),
    ("proto/payload.rs", include_str!("../proto/payload.rs")),
    (
        "proto/payload/tests.rs",
        include_str!("../proto/payload/tests.rs"),
    ),
    ("session.rs", include_str!("../session.rs")),
    ("session/expiry.rs", include_str!("../session/expiry.rs")),
    ("session/channel.rs", include_str!("../session/channel.rs")),
    (
        "session/channel/tests.rs",
        include_str!("../session/channel/tests.rs"),
    ),
    (
        "session/channel/headroom.rs",
        include_str!("../session/channel/headroom.rs"),
    ),
    (
        "session/channel/outbox.rs",
        include_str!("../session/channel/outbox.rs"),
    ),
    (
        "session/channel/send.rs",
        include_str!("../session/channel/send.rs"),
    ),
    (
        "session/channel/own_key.rs",
        include_str!("../session/channel/own_key.rs"),
    ),
    (
        "session/channel/receive.rs",
        include_str!("../session/channel/receive.rs"),
    ),
    (
        "session/channel/tests/receive.rs",
        include_str!("../session/channel/tests/receive.rs"),
    ),
    (
        "session/channel/status.rs",
        include_str!("../session/channel/status.rs"),
    ),
    (
        "session/channel/sync.rs",
        include_str!("../session/channel/sync.rs"),
    ),
    (
        "session/channel/tests/status.rs",
        include_str!("../session/channel/tests/status.rs"),
    ),
    (
        "session/channel/tests/sync.rs",
        include_str!("../session/channel/tests/sync.rs"),
    ),
    (
        "session/channel/tests/outbox.rs",
        include_str!("../session/channel/tests/outbox.rs"),
    ),
    (
        "session/channel/tests/headroom.rs",
        include_str!("../session/channel/tests/headroom.rs"),
    ),
    (
        "session/channel/tests/send.rs",
        include_str!("../session/channel/tests/send.rs"),
    ),
];

/// Spec 010, R1: `crypto/ffi.rs` is the only file that uses the keyword, and
/// it carries the two attributes that make its blocks reviewable.
#[test]
fn s010_t01_r01_unsafe_only_in_ffi() {
    // Assembled from two pieces so that this file does not contain the keyword
    // it searches for, which would make the test report itself.
    let keyword = concat!("un", "safe");
    for (name, source) in SOURCES {
        // Prose names the keyword and lint names embed it; only code uses it.
        let code: String = source
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<&str>>()
            .join("\n");
        assert_eq!(
            uses_keyword(&code, keyword),
            name == "crypto/ffi.rs",
            "{name}"
        );
    }
    let ffi = include_str!("ffi.rs");
    assert!(ffi.contains("#![allow(unsafe_code)]"));
    assert!(ffi.contains("#![deny(unsafe_op_in_unsafe_fn)]"));
    assert_eq!(
        ffi.matches("// SAFETY:").count(),
        ffi.matches(concat!("un", "safe {")).count(),
        "every block carries a SAFETY comment"
    );
}

/// Whether `code` uses `keyword` as a word, so that a lint name that embeds
/// it (`undocumented_<keyword>_blocks`) does not count as a use.
fn uses_keyword(code: &str, keyword: &str) -> bool {
    let is_identifier = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    code.match_indices(keyword).any(|(at, _)| {
        !is_identifier(code[..at].chars().next_back())
            && !is_identifier(code[at + keyword.len()..].chars().next())
    })
}

/// Spec 010, R2: the initialisation runs once per process and returns a value
/// on failure instead of panicking.
#[test]
fn s010_t02_r02_init_runs_once() {
    assert_eq!(init(), Ok(()));
    assert_eq!(init(), Ok(()));
    assert_eq!(init_calls(), 1);
}

/// Spec 010, R3: every secret prints as the literal `[REDACTED]`, and the
/// types listed in `SECRET_TYPES` are the ones this spec instantiates and
/// `StorageKey` of spec 020 (R24).
#[test]
fn s010_t03_r03_debug_is_redacted() {
    let short = Secret::<32>::from_bytes([7u8; 32]);
    let long = Secret::<64>::from_bytes([9u8; 64]);
    assert_eq!(format!("{short:?}"), "[REDACTED]");
    assert_eq!(format!("{long:?}"), "[REDACTED]");
    let storage_key = crate::storage::StorageKey::from_bytes(&mut [8u8; 32]);
    assert_eq!(format!("{storage_key:?}"), "[REDACTED]");
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>", "StorageKey"]);
}

/// Spec 010, R3: `Secret` implements nothing that could copy it, order it,
/// print it or hand out its bytes. Checked over the source because a
/// `compile_fail` doctest cannot reach a `pub(crate)` type (see 010-T04).
#[test]
fn s010_t04_r03_secret_has_no_forbidden_traits() {
    let source = include_str!("secret.rs");
    let impls: Vec<&str> = source.lines().filter(|l| l.starts_with("impl")).collect();
    assert_eq!(
        impls,
        [
            "impl<const N: usize> Secret<N> {",
            "impl<const N: usize> fmt::Debug for Secret<N> {",
            "impl<const N: usize> PartialEq for Secret<N> {",
        ]
    );
    assert!(source.contains("#[derive(Zeroize, ZeroizeOnDrop)]"));
    assert_eq!(source.matches("#[derive(").count(), 1);
    // No other file of the crate implements a trait for `Secret` either,
    // written with a path or without.
    for (name, source) in SOURCES {
        let elsewhere = source.lines().any(|line| {
            line.trim_start().starts_with("impl")
                && line
                    .split_once(" for ")
                    .is_some_and(|(_, rest)| rest.contains("Secret<"))
        });
        assert!(name == "crypto/secret.rs" || !elsewhere, "{name}");
    }
}

proptest! {
    /// Spec 010, R4: the constant-time comparison answers what `==` answers.
    #[test]
    fn s010_t05_r04_ct_eq_agrees_with_equality(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        assert_eq!(ct_eq(&a, &b), a == b);
        assert!(ct_eq(&a, &a));
        for at in [0, 15, 31] {
            let mut flipped = a;
            flipped[at] ^= 1;
            assert!(!ct_eq(&a, &flipped), "byte {at}");
        }
    }
}

/// Spec 010, R4: the fixed-size public types compare every byte, the first
/// and the last included, as the known-answer tests that rely on them need.
#[test]
fn s010_t05_r04_public_types_compare_every_byte() {
    fn flips<const N: usize>(bytes: [u8; N]) -> [[u8; N]; 2] {
        let (mut first, mut last) = (bytes, bytes);
        first[0] ^= 1;
        last[N - 1] ^= 1;
        [first, last]
    }
    let base = [7u8; 64];
    assert!(Signature(base) == Signature(base));
    for other in flips(base) {
        assert!(Signature(base) != Signature(other));
    }
    let key = [7u8; 32];
    assert!(PublicKey(key) == PublicKey(key));
    for other in flips(key) {
        assert!(PublicKey(key) != PublicKey(other));
    }
    let nonce = [7u8; 24];
    assert!(Nonce(nonce) == Nonce(nonce));
    for other in flips(nonce) {
        assert!(Nonce(nonce) != Nonce(other));
    }
    let salt = [7u8; 16];
    assert!(Salt(salt) == Salt(salt));
    for other in flips(salt) {
        assert!(Salt(salt) != Salt(other));
    }
}

/// Spec 010, R5: randomness comes from libsodium and is not a constant.
#[test]
fn s010_t06_r05_random_bytes_differ() -> Result<(), CryptoError> {
    assert_ne!(random_bytes::<32>()?, random_bytes::<32>()?);
    // Every byte is drawn, the last ones included, also into a secret.
    let (first, second) = (random_bytes::<64>()?, random_bytes::<64>()?);
    assert_ne!(first[32..], second[32..]);
    let (first, second) = (Secret::<64>::random()?, Secret::<64>::random()?);
    assert_ne!(first.expose()[32..], second.expose()[32..]);
    let (mut secret_last, mut array_last) = (0u8, 0u8);
    for _ in 0..8 {
        secret_last |= Secret::<64>::random()?.expose()[63];
        array_last |= random_bytes::<64>()?[63];
    }
    assert_ne!(secret_last, 0);
    assert_ne!(array_last, 0);
    assert_ne!(Secret::<32>::random()?.expose(), &[0u8; 32]);
    Ok(())
}

/// Spec 010, R15: seven unit variants, in the order the spec fixes.
#[test]
fn s010_t23_r15_error_variants_are_unit_and_ordered() {
    let names: Vec<String> = [
        CryptoError::InitFailed,
        CryptoError::TooLong,
        CryptoError::BadLength,
        CryptoError::Forged,
        CryptoError::BadPadding,
        CryptoError::OutOfMemory,
        CryptoError::BadEncoding,
    ]
    .iter()
    .map(|variant| format!("{variant:?}"))
    .collect();
    assert_eq!(
        names,
        [
            "InitFailed",
            "TooLong",
            "BadLength",
            "Forged",
            "BadPadding",
            "OutOfMemory",
            "BadEncoding"
        ]
    );

    let source = include_str!("../crypto.rs");
    let header = "enum CryptoError {";
    let start = source.find(header).unwrap() + header.len();
    let body = &source[start..start + source[start..].find('}').unwrap()];
    assert!(!body.contains('('), "no variant carries data");
    let mut cursor = 0;
    for name in &names {
        let at = body.find(name.as_str()).expect("variant in the source");
        assert!(at > cursor, "{name} is out of order");
        cursor = at;
    }
}

/// Spec 010, R15: a public key shows four bytes; the rest of the public data
/// shows in full. No type prints anything a log should not carry.
#[test]
fn s010_t24_r15_public_key_debug_is_prefix() {
    let mut key = [0u8; 32];
    key[0] = 0xab;
    key[1] = 0xcd;
    key[2] = 0xef;
    key[3] = 0x01;
    assert_eq!(format!("{:?}", PublicKey(key)), "abcdef01…");
    assert_eq!(format!("{:?}", Nonce([0x0a; 24])), "0a".repeat(24));
    assert_eq!(format!("{:?}", Salt([0x0b; 16])), "0b".repeat(16));
    assert_eq!(format!("{:?}", Signature([0x0c; 64])), "0c".repeat(64));
    assert_eq!(
        format!("{:?}", KdfContext::new(*b"pcchan01")),
        "70636368616e3031"
    );
}

/// Spec 010, R16: the manifest pins the two dependencies of `core` and the
/// single dev dependency, and never asks libsodium of the host.
#[test]
fn s010_t25_r16_manifest_pins_dependencies() {
    let dependencies = manifest_section("[dependencies]");
    let declarations = declarations(&dependencies);
    assert_eq!(declarations.len(), 2);
    for crate_name in ["libsodium-sys-stable", "zeroize"] {
        assert!(
            declarations.iter().any(|line| line.starts_with(crate_name)),
            "{crate_name}"
        );
    }
    for feature in ["use-pkg-config", "minimal", "fetch-latest"] {
        assert!(
            !declarations.iter().any(|line| line.contains(feature)),
            "{feature} is named in a comment that keeps it off, never enabled"
        );
    }
    assert!(manifest_section("[dev-dependencies]").contains("proptest"));
}

/// The body of one section of `crates/core/Cargo.toml`.
fn manifest_section(name: &str) -> String {
    let manifest = include_str!("../../Cargo.toml");
    let start = manifest.find(name).expect("section");
    let rest = &manifest[start + name.len()..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// The declarations of a manifest section. Comments are prose: what counts is
/// what the manifest declares.
fn declarations(section: &str) -> Vec<&str> {
    section
        .lines()
        .filter(|line| line.contains(" = ") && !line.trim_start().starts_with('#'))
        .map(str::trim)
        .collect()
}

/// Spec 020, R2: `secretbox_open` hands its plaintext back in a buffer wiped
/// on drop, and the one feature of `core`, `test-support`, enables nothing:
/// no feature and no optional dependency, which would be a third dependency
/// behind it (T25 still counts two).
#[test]
fn s020_t02_r02_amended_wrapper() -> Result<(), CryptoError> {
    let key = Secret::<32>::from_bytes([17u8; 32]);
    let nonce = Nonce([18u8; 24]);
    let sealed = secretbox_seal(&key, &nonce, b"state")?;
    let opened: Zeroizing<Vec<u8>> = secretbox_open(&key, &nonce, &sealed)?;
    assert_eq!(opened.as_slice(), b"state");
    let features = manifest_section("[features]");
    assert_eq!(declarations(&features), ["test-support = []"]);
    assert!(!manifest_section("[dependencies]").contains("optional"));
    Ok(())
}

/// Spec 010, R17: the clock, the file system and the network are unreachable
/// from a crate that must not touch them (AGENTS 10).
#[test]
fn s010_t26_r17_clippy_toml_disallows_clock_fs_net() {
    let clippy = include_str!("../../../../clippy.toml");
    // Each entry's path, read whole, so that `std::fs::read` is not found
    // inside `std::fs::read_to_string`; each entry cites AGENTS 10.
    let mut listed: Vec<&str> = Vec::new();
    for line in clippy.lines().filter(|line| line.contains("{ path = ")) {
        let path = line.split('"').nth(1).unwrap();
        assert!(line.contains("AGENTS 10"), "{path}");
        listed.push(path);
    }
    listed.sort_unstable();
    let mut required = vec![
        "std::time::SystemTime::now",
        "std::time::Instant::now",
        "std::thread::sleep",
        "std::fs::read",
        "std::fs::write",
        "std::fs::File::open",
        "std::fs::File::create",
        "std::net::TcpStream::connect",
        "std::time::SystemTime::elapsed",
        "std::time::Instant::elapsed",
        "std::fs::read_to_string",
        "std::fs::read_dir",
        "std::fs::create_dir_all",
        "std::fs::remove_file",
        "std::fs::rename",
        "std::fs::File::options",
        "std::fs::OpenOptions::open",
        "std::net::TcpListener::bind",
        "std::net::UdpSocket::bind",
        "std::env::var",
        "std::fs::remove_dir_all",
        "std::fs::create_dir",
        "std::fs::metadata",
        "std::path::Path::exists",
        "std::path::Path::try_exists",
        "std::path::Path::is_dir",
        "std::path::Path::is_file",
        "std::path::Path::metadata",
        "std::path::Path::read_dir",
        "std::path::Path::canonicalize",
        "std::path::Path::is_symlink",
        "std::path::Path::symlink_metadata",
        "std::path::Path::read_link",
        "std::fs::exists",
        "std::fs::copy",
        "std::fs::remove_dir",
        "std::fs::symlink_metadata",
        "std::fs::read_link",
        "std::fs::hard_link",
        "std::fs::set_permissions",
        "std::fs::canonicalize",
        "std::process::Command::new",
        "std::env::var_os",
        "std::env::vars",
    ];
    required.sort_unstable();
    assert_eq!(listed, required);
}

/// Spec 010, R18: zeroizing leaves every byte at zero.
#[test]
fn s010_t27_r18_zeroize_clears_bytes() {
    let mut short = Secret::<32>::from_bytes([1u8; 32]);
    short.zeroize();
    assert_eq!(short.expose(), &[0u8; 32]);
    let mut long = Secret::<64>::from_bytes([2u8; 64]);
    long.zeroize();
    assert_eq!(long.expose(), &[0u8; 64]);
}

/// Spec 010, R16: the SHA-256 of the build script is pinned, so a change in
/// how libsodium is obtained cannot arrive unread.
#[test]
fn s010_t28_r16_deny_pins_the_build_script() {
    let deny = include_str!("../../../../deny.toml");
    let start = deny.find("[[bans.build.bypass]]").expect("bypass entry");
    let entry = &deny[start..];
    assert!(entry.contains("crate = \"libsodium-sys-stable\""));
    let hash = entry
        .lines()
        .find_map(|line| line.strip_prefix("build-script = \""))
        .expect("build-script hash");
    assert_eq!(hash.trim_end_matches('"').len(), 64);
}

/// Spec 010, R16: the libsodium actually linked is the version this spec
/// pins. The manifest pins the crate; only this asks the library.
#[test]
fn s010_t29_r16_libsodium_version_is_pinned() -> Result<(), CryptoError> {
    assert_eq!(version()?, "1.0.22");
    Ok(())
}

/// Spec 010, R6: the AEAD reproduces the published vector, in both
/// directions.
#[test]
fn s010_t07_r06_aead_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "aead_xchacha20poly1305_ietf");
    let key = Secret::<32>::from_bytes(vector.input("key").array());
    let nonce = Nonce(vector.input("nonce").array());
    let aad = vector.input("aad").bytes();
    let plaintext = vector.input("plaintext").bytes();
    let ciphertext = vector.expected("ciphertext").bytes();
    assert_eq!(aead_encrypt(&key, &nonce, aad, plaintext)?, ciphertext);
    assert_eq!(aead_decrypt(&key, &nonce, aad, ciphertext)?, plaintext);
    Ok(())
}

proptest! {
    /// Spec 010, R6: what the AEAD seals it opens, and the tag costs exactly
    /// sixteen bytes.
    #[test]
    fn s010_t08_r06_aead_roundtrip(
        plaintext in bytes_of(any::<u8>(), 0..=4096),
        aad in bytes_of(any::<u8>(), 0..=128),
    ) {
        let key = Secret::<32>::from_bytes([3u8; 32]);
        let nonce = Nonce([4u8; 24]);
        let sealed = aead_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + 16);
        assert_eq!(aead_decrypt(&key, &nonce, &aad, &sealed).unwrap(), plaintext);
    }
}

/// Spec 010, R6: one byte changed anywhere — ciphertext, tag, associated
/// data or nonce — and the AEAD reports a forgery.
#[test]
fn s010_t09_r06_aead_mutation() -> Result<(), CryptoError> {
    let key = Secret::<32>::from_bytes([5u8; 32]);
    let nonce = Nonce([6u8; 24]);
    let aad = [7u8; 12];
    let plaintext = [8u8; 64];
    let sealed = aead_encrypt(&key, &nonce, &aad, &plaintext)?;

    // The body of the ciphertext and its tag, one flipped byte at a time.
    for at in [0, 63, 64, sealed.len() - 1] {
        let mut broken = sealed.clone();
        broken[at] ^= 1;
        assert_eq!(
            aead_decrypt(&key, &nonce, &aad, &broken),
            Err(CryptoError::Forged),
            "ciphertext byte {at}"
        );
    }

    let mut other_aad = aad;
    other_aad[0] ^= 1;
    assert_eq!(
        aead_decrypt(&key, &nonce, &other_aad, &sealed),
        Err(CryptoError::Forged)
    );

    let mut other_nonce = nonce;
    other_nonce.0[0] ^= 1;
    assert_eq!(
        aead_decrypt(&key, &other_nonce, &aad, &sealed),
        Err(CryptoError::Forged)
    );
    // A ciphertext shorter than its tag is a forgery too.
    assert_eq!(
        aead_decrypt(&key, &nonce, &aad, &[0u8; 15]),
        Err(CryptoError::Forged)
    );
    Ok(())
}

proptest! {
    /// Spec 010, R7: the stream cipher is its own inverse.
    #[test]
    fn s010_t10_r07_stream_xor_is_involution(plaintext in bytes_of(any::<u8>(), 0..=4096)) {
        let key = Secret::<32>::from_bytes([9u8; 32]);
        let nonce = Nonce([10u8; 24]);
        let mut buffer = plaintext.clone();
        stream_xor(&key, &nonce, &mut buffer).unwrap();
        stream_xor(&key, &nonce, &mut buffer).unwrap();
        assert_eq!(buffer, plaintext);
    }
}

/// Spec 010, R7: over a zero buffer the stream cipher writes the published
/// keystream.
#[test]
fn s010_t11_r07_stream_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "stream_xchacha20");
    let key = Secret::<32>::from_bytes(vector.input("key").array());
    let nonce = Nonce(vector.input("nonce").array());
    let mut buffer = vector.input("buf").bytes().to_vec();
    stream_xor(&key, &nonce, &mut buffer)?;
    assert_eq!(buffer, vector.expected("buf").bytes());
    Ok(())
}

/// Spec 010, R12: the secret box reproduces the published vector.
#[test]
fn s010_t18_r12_secretbox_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "secretbox_easy");
    let key = Secret::<32>::from_bytes(vector.input("key").array());
    let nonce = Nonce(vector.input("nonce").array());
    let plaintext = vector.input("plaintext").bytes();
    let sealed = vector.expected("sealed").bytes();
    assert_eq!(secretbox_seal(&key, &nonce, plaintext)?, sealed);
    assert_eq!(secretbox_open(&key, &nonce, sealed)?.as_slice(), plaintext);
    Ok(())
}

/// Spec 010, R12: what it seals it opens, a flipped byte is a forgery, and a
/// ciphertext too short to hold a tag is one too.
#[test]
fn s010_t19_r12_secretbox_roundtrip_and_mutation() -> Result<(), CryptoError> {
    let key = Secret::<32>::from_bytes([11u8; 32]);
    let nonce = Nonce([12u8; 24]);
    let plaintext = [13u8; 100];
    let sealed = secretbox_seal(&key, &nonce, &plaintext)?;
    assert_eq!(sealed.len(), plaintext.len() + 16);
    assert_eq!(secretbox_open(&key, &nonce, &sealed)?.as_slice(), plaintext);

    for at in [0, 15, 16, sealed.len() - 1] {
        let mut broken = sealed.clone();
        broken[at] ^= 1;
        assert_eq!(
            secretbox_open(&key, &nonce, &broken),
            Err(CryptoError::Forged),
            "byte {at}"
        );
    }
    assert_eq!(
        secretbox_open(&key, &nonce, &[0u8; 15]),
        Err(CryptoError::Forged)
    );
    Ok(())
}

/// Spec 010, R14: the wrapper bounds only what libsodium requires. A
/// megabyte is far above every protocol bound and goes through untouched;
/// what it does reject is the arithmetic that would not fit.
#[test]
fn s010_t22_r14_wrapper_bounds_are_the_primitives() -> Result<(), CryptoError> {
    let key = Secret::<32>::from_bytes([14u8; 32]);
    let nonce = Nonce([15u8; 24]);
    let plaintext = vec![16u8; 1024 * 1024];
    let sealed = aead_encrypt(&key, &nonce, &[], &plaintext)?;
    assert_eq!(aead_decrypt(&key, &nonce, &[], &sealed)?, plaintext);
    let boxed = secretbox_seal(&key, &nonce, &plaintext)?;
    assert_eq!(secretbox_open(&key, &nonce, &boxed)?.as_slice(), plaintext);

    assert_eq!(checked_output_len(100, 16), Ok(116));
    assert_eq!(
        checked_output_len(usize::MAX - 15, 16),
        Err(CryptoError::TooLong)
    );
    assert_eq!(checked_output_len(usize::MAX, 1), Err(CryptoError::TooLong));

    assert_eq!(check_password_len(0), Err(CryptoError::BadLength));
    assert_eq!(check_password_len(2048), Ok(()));
    assert_eq!(ffi::password_max(), 4_294_967_295);
    if let Ok(max) = usize::try_from(ffi::password_max()) {
        assert_eq!(check_password_len(max), Ok(()));
    }
    let salt = Salt([17u8; 16]);
    assert_eq!(password_key(b"", &salt).err(), Some(CryptoError::BadLength));
    let beyond_libsodium = usize::try_from(ffi::password_max())
        .ok()
        .and_then(|max| max.checked_add(1));
    if let Some(len) = beyond_libsodium {
        assert_eq!(check_password_len(len), Err(CryptoError::TooLong));
    }

    // The edge lengths: an empty and a large buffer through the stream, and
    // the BLAKE2b-256 of nothing, computed with Python's hashlib.
    let stream_key = Secret::<32>::from_bytes([18u8; 32]);
    for len in [0, 1024 * 1024] {
        let mut buffer = vec![19u8; len];
        stream_xor(&stream_key, &nonce, &mut buffer)?;
        if let Some(tail) = buffer
            .get(len.saturating_sub(64)..)
            .filter(|t| !t.is_empty())
        {
            assert_ne!(tail, &[19u8; 64][..], "the keystream reaches the end");
        }
        stream_xor(&stream_key, &nonce, &mut buffer)?;
        assert_eq!(buffer, vec![19u8; len], "{len}");
    }
    // A ciphertext that is a tag alone, for the empty plaintext, is forged
    // unless the tag verifies.
    for tag_only in [[0u8; super::TAG_LEN], [0xffu8; super::TAG_LEN]] {
        assert_eq!(
            aead_decrypt(&key, &nonce, &[], &tag_only),
            Err(CryptoError::Forged)
        );
        assert_eq!(
            secretbox_open(&key, &nonce, &tag_only),
            Err(CryptoError::Forged)
        );
    }
    let empty: [u8; 32] = core::array::from_fn(|at| {
        let hex = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
        u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap()
    });
    assert_eq!(hash(b"")?, empty);
    assert_ne!(keyed_hash(&stream_key, b"")?.expose(), &empty);

    let mut buffer = vec![0u8; 8];
    assert_eq!(pad(&mut buffer, 0), Err(CryptoError::BadLength));
    assert_eq!(unpad(&buffer, 0), Err(CryptoError::BadLength));
    Ok(())
}

/// Spec 010, R8: the derivation reproduces its vector, and a different
/// context gives a different subkey.
#[test]
fn s010_t12_r08_kdf_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "kdf_subkey_0");
    let key = Secret::<32>::from_bytes(vector.input("key").array());
    let context = KdfContext::new(vector.input("context").array());
    let expected = Secret::<32>::from_bytes(vector.expected("subkey").array());
    assert!(kdf_derive(&key, &context)? == expected);

    let other = KdfContext::new(*b"pcother1");
    assert!(kdf_derive(&key, &other)? != expected);
    Ok(())
}

/// Spec 010, R9: BLAKE2b at 32 bytes, keyed and unkeyed, on their vectors.
#[test]
fn s010_t13_r09_hash_known_answer() -> Result<(), CryptoError> {
    let unkeyed = vectors::load("010", "blake2b_256_unkeyed");
    assert_eq!(
        hash(unkeyed.input("input").bytes())?.to_vec(),
        unkeyed.expected("hash").bytes()
    );

    let keyed = vectors::load("010", "blake2b_256_keyed");
    let key = Secret::<32>::from_bytes(keyed.input("key").array());
    let expected = Secret::<32>::from_bytes(keyed.expected("hash").array());
    assert!(keyed_hash(&key, keyed.input("input").bytes())? == expected);
    Ok(())
}

/// Spec 010, R10: the three RFC 8032 vectors, seed to public key and message
/// to signature.
#[test]
fn s010_t14_r10_sign_known_answer() -> Result<(), CryptoError> {
    for name in [
        "ed25519_rfc8032_test1",
        "ed25519_rfc8032_test2",
        "ed25519_rfc8032_test3",
    ] {
        let vector = vectors::load("010", name);
        let seed = Secret::<32>::from_bytes(vector.input("seed").array());
        let message = vector.input("message").bytes();
        let (public_key, secret_key) = sign_keypair_from_seed(&seed)?;
        assert!(
            public_key == PublicKey(vector.expected("pk").array()),
            "{name}"
        );
        let signature = sign_detached(&secret_key, message)?;
        assert!(
            signature == Signature(vector.expected("signature").array()),
            "{name}"
        );
        verify_detached(&public_key, message, &signature)?;
    }
    Ok(())
}

/// The cases of ed25519-speccheck libsodium rejects: every one but case 3.
const SPECCHECK_REJECTED: [&str; 11] = [
    "speccheck_0",
    "speccheck_1",
    "speccheck_2",
    "speccheck_4",
    "speccheck_5",
    "speccheck_6",
    "speccheck_7",
    "speccheck_8",
    "speccheck_9",
    "speccheck_10",
    "speccheck_11",
];

/// Spec 010, R10: verification is strict. Every malformed signature or key
/// of the negative vectors is a forgery, never an accepted message. Of the
/// published ed25519-speccheck cases, 0–2, 6, 7 and 11 are accepted by a
/// common verifier without the strict checks, 4, 5 and 8–10 pin the
/// cofactorless equation and the comparison of `R`, and case 3, a valid
/// signature over mixed-order points, verifies (ADR 0042).
#[test]
fn s010_t15_r10_verify_rejects_malformed() {
    let named = [
        "signature_s_plus_l",
        "pk_order_4",
        "pk_not_on_curve",
        "pk_non_canonical",
        "r_wrong_point",
        "wrong_message",
        "wrong_pk",
    ];
    for name in named.into_iter().chain(SPECCHECK_REJECTED) {
        let vector = vectors::load("010", name);
        assert_eq!(vector.kind(), Kind::Negative);
        assert_eq!(vector.expected("error").text(), "Forged", "{name}");
        let public_key = PublicKey(vector.input("pk").array());
        let signature = Signature(vector.input("signature").array());
        assert_eq!(
            verify_detached(&public_key, vector.input("message").bytes(), &signature),
            Err(CryptoError::Forged),
            "{name}"
        );
    }
    let valid = vectors::load("010", "speccheck_3");
    assert_eq!(valid.kind(), Kind::Positive);
    assert!(valid.expected("valid").flag());
    let public_key = PublicKey(valid.input("pk").array());
    let signature = Signature(valid.input("signature").array());
    let message = valid.input("message").bytes();
    assert_eq!(verify_detached(&public_key, message, &signature), Ok(()));
}

proptest! {
    /// Spec 010, R10: a fresh key signs its own messages and nobody else's.
    #[test]
    fn s010_t16_r10_sign_roundtrip(message in bytes_of(any::<u8>(), 0..=4096)) {
        let (public_key, secret_key) = sign_keypair().unwrap();
        let signature = sign_detached(&secret_key, &message).unwrap();
        assert_eq!(verify_detached(&public_key, &message, &signature), Ok(()));

        let (other_key, _) = sign_keypair().unwrap();
        assert_eq!(
            verify_detached(&other_key, &message, &signature),
            Err(CryptoError::Forged)
        );
    }
}

/// Spec 010, R11: Argon2id13 at the parameters the specification fixes, and
/// a different salt gives a different key.
#[test]
fn s010_t17_r11_password_key_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "argon2id13_interactive");
    assert_eq!(vector.input("opslimit").number(), 2);
    assert_eq!(vector.input("memlimit").number(), 67_108_864);
    let password = vector.input("password").bytes();
    let salt = Salt(vector.input("salt").array());
    let expected = Secret::<32>::from_bytes(vector.expected("key").array());
    assert!(password_key(password, &salt)? == expected);

    let mut other = salt;
    other.0[0] ^= 1;
    assert!(password_key(password, &other)? != expected);
    Ok(())
}

proptest! {
    /// Spec 010, R13: padding grows the buffer to the next multiple of the
    /// block, always strictly, and unpadding gives the length back.
    #[test]
    fn s010_t20_r13_pad_unpad_roundtrip(
        plaintext in bytes_of(any::<u8>(), 0..=4096),
        block in proptest::sample::select(vec![16usize, 1024]),
    ) {
        let mut buffer = plaintext.clone();
        pad(&mut buffer, block).unwrap();
        assert!(buffer.len() > plaintext.len());
        assert_eq!(buffer.len() % block, 0);
        assert_eq!(unpad(&buffer, block).unwrap(), plaintext.len());
        assert_eq!(&buffer[..plaintext.len()], &plaintext[..]);
    }
}

/// Spec 010, R13: the padding vector, the two buffers that carry no valid
/// padding at all, and a buffer that is not a whole number of blocks, which
/// libsodium unpads from its last block: the length is the caller's to check
/// (specs 011 and 013 do).
#[test]
fn s010_t21_r13_unpad_rejects_bad_padding() -> Result<(), CryptoError> {
    let vector = vectors::load("010", "pad_1024");
    let block = usize::try_from(vector.input("block").number()).unwrap();
    let mut buffer = vector.input("buf").bytes().to_vec();
    let unpadded_len = buffer.len();
    pad(&mut buffer, block)?;
    assert_eq!(buffer, vector.expected("padded").bytes());
    assert_eq!(unpad(&buffer, block)?, unpadded_len);

    let zeros = vectors::load("010", "unpad_all_zero");
    assert_eq!(zeros.expected("error").text(), "BadPadding");
    assert_eq!(
        unpad(
            zeros.input("buf").bytes(),
            usize::try_from(zeros.input("block").number()).unwrap()
        ),
        Err(CryptoError::BadPadding)
    );
    assert_eq!(unpad(&[0u8; 15], 16), Err(CryptoError::BadPadding));
    let mut not_a_multiple = [0u8; 30];
    not_a_multiple[29] = 0x80;
    assert_eq!(unpad(&not_a_multiple, 16), Ok(29));
    Ok(())
}

/// The wrappers of `ffi.rs` check the buffer sizes their SAFETY comments
/// rest on, so a caller that sized one wrong is refused instead of writing
/// outside it. It covers no requirement of the spec: it guards the one file
/// where `unsafe` lives.
#[test]
fn ffi_rejects_a_buffer_of_the_wrong_size() {
    let key = [1u8; 32];
    let nonce = [2u8; 24];
    let mut too_small = [0u8; 8];
    assert!(!ffi::aead_encrypt(
        &key,
        &nonce,
        &[],
        &[3u8; 16],
        &mut too_small
    ));
    assert!(!ffi::aead_decrypt(
        &key,
        &nonce,
        &[],
        &[4u8; 32],
        &mut too_small
    ));
    assert!(!ffi::secretbox_seal(
        &key,
        &nonce,
        &[5u8; 16],
        &mut too_small
    ));
    assert!(!ffi::secretbox_open(
        &key,
        &nonce,
        &[6u8; 32],
        &mut too_small
    ));
    let mut buffer = [0u8; 16];
    assert!(!ffi::pad(&mut buffer, 17, 16));
    // One byte too large, over a real seal, so that only the size check
    // can refuse the call.
    let plaintext = [7u8; 20];
    let mut sealed = [0u8; 36];
    assert!(ffi::aead_encrypt(
        &key,
        &nonce,
        &[],
        &plaintext,
        &mut sealed
    ));
    assert!(!ffi::aead_encrypt(
        &key,
        &nonce,
        &[],
        &plaintext,
        &mut [0u8; 37]
    ));
    assert!(!ffi::aead_decrypt(
        &key,
        &nonce,
        &[],
        &sealed,
        &mut [0u8; 21]
    ));
    // One byte too small too: a real seal, so the tag would verify.
    assert!(!ffi::aead_decrypt(
        &key,
        &nonce,
        &[],
        &sealed,
        &mut [0u8; 19]
    ));
    assert!(ffi::secretbox_seal(&key, &nonce, &plaintext, &mut sealed));
    assert!(!ffi::secretbox_open(&key, &nonce, &sealed, &mut [0u8; 19]));
    assert!(!ffi::secretbox_seal(
        &key,
        &nonce,
        &plaintext,
        &mut [0u8; 37]
    ));
    assert!(!ffi::secretbox_open(&key, &nonce, &sealed, &mut [0u8; 21]));
    let mut wiped = [1u8; 32];
    ffi::memzero(&mut wiped);
    assert_eq!(wiped, [0u8; 32]);
    // `bin2base64` needs room for the text and its terminator: 4 + 1 here.
    assert!(!ffi::bin2base64(&mut [0u8; 4], b"foo"));
    assert!(ffi::bin2base64(&mut [0u8; 5], b"foo"));
}

/// Spec 010, R19: libsodium's URL-safe base64 with no padding, strict: the
/// RFC 4648 §10 test vectors in the URL-safe alphabet, and each way a text
/// can fail to be the one encoding of some bytes.
#[test]
fn s010_t30_r19_base64url_is_strict() -> Result<(), CryptoError> {
    let known: [(&[u8], &[u8]); 9] = [
        (b"", b""),
        (b"f", b"Zg"),
        (b"fo", b"Zm8"),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy"),
        (b"\xfb\xef", b"--8"),
        (b"\xff", b"_w"),
    ];
    for (bin, text) in known {
        let encoded = base64url_encode(bin)?;
        assert_eq!(encoded.as_slice(), text);
        assert_eq!(encoded.capacity(), text.len() + 1, "text and terminator");
        let decoded = base64url_decode(text)?;
        assert_eq!(decoded.as_slice(), bin);
        assert_eq!(decoded.capacity(), bin.len());
    }
    for text in [
        &b"Zg=="[..],
        b"Zg=",
        b"Zm9v+A",
        b"Zm9v/A",
        b"Zh",
        b"Zm9",
        b"Zm-",
        b"Zm9vY",
        b"A",
        b" Zg",
        b"Zg\n",
        b"Z\x00g",
        "Zé".as_bytes(),
    ] {
        assert_eq!(
            base64url_decode(text).err(),
            Some(CryptoError::BadEncoding),
            "{text:?}"
        );
    }
    Ok(())
}

proptest! {
    /// Spec 010, R19: decode(encode(x)) = x, and the text uses only the
    /// URL-safe alphabet.
    #[test]
    fn s010_t31_r19_base64url_round_trip(bin in bytes_of(any::<u8>(), 0..=1_024)) {
        let text = base64url_encode(&bin).unwrap();
        assert!(text.iter().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(byte)));
        assert_eq!(base64url_decode(&text).unwrap().as_slice(), bin.as_slice());
    }
}
