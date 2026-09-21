//! Tests of spec 010: the invariants of the module itself (confinement of
//! `unsafe`, initialisation, secrets, randomness, redacted output), the pins
//! of its build, and every primitive against the vectors of `010.json`.

use proptest::collection::vec as bytes_of;
use proptest::prelude::{any, proptest};
use zeroize::Zeroize;

use super::{
    CryptoError, KdfContext, Nonce, PublicKey, SECRET_TYPES, Salt, Secret, Signature, aead_decrypt,
    aead_encrypt, checked_output_len, ct_eq, hash, init, init_calls, kdf_derive, keyed_hash,
    random_bytes, secretbox_open, secretbox_seal, sign_detached, sign_keypair,
    sign_keypair_from_seed, stream_xor, vectors, verify_detached, version,
};

/// Every `.rs` file of the crate. `core` does no I/O (AGENTS 10), so the test
/// cannot walk the directory: a new file is added to this list by hand.
const SOURCES: [(&str, &str); 6] = [
    ("lib.rs", include_str!("../lib.rs")),
    ("crypto.rs", include_str!("../crypto.rs")),
    ("crypto/ffi.rs", include_str!("ffi.rs")),
    ("crypto/secret.rs", include_str!("secret.rs")),
    ("crypto/tests.rs", include_str!("tests.rs")),
    ("crypto/vectors.rs", include_str!("vectors.rs")),
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
/// types listed in `SECRET_TYPES` are the ones this spec instantiates.
#[test]
fn s010_t03_r03_debug_is_redacted() {
    let short = Secret::<32>::from_bytes([7u8; 32]);
    let long = Secret::<64>::from_bytes([9u8; 64]);
    assert_eq!(format!("{short:?}"), "[REDACTED]");
    assert_eq!(format!("{long:?}"), "[REDACTED]");
    assert_eq!(SECRET_TYPES, ["Secret<32>", "Secret<64>"]);
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
}

proptest! {
    /// Spec 010, R4: the constant-time comparison answers what `==` answers.
    #[test]
    fn s010_t05_r04_ct_eq_agrees_with_equality(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        assert_eq!(ct_eq(&a, &b), a == b);
        assert!(ct_eq(&a, &a));
    }
}

/// Spec 010, R5: randomness comes from libsodium and is not a constant.
#[test]
fn s010_t06_r05_random_bytes_differ() -> Result<(), CryptoError> {
    assert_ne!(random_bytes::<32>()?, random_bytes::<32>()?);
    assert_ne!(Secret::<32>::random()?.expose(), &[0u8; 32]);
    Ok(())
}

/// Spec 010, R15: six unit variants, in the order the spec fixes.
#[test]
fn s010_t23_r15_error_variants_are_unit_and_ordered() {
    let names: Vec<String> = [
        CryptoError::InitFailed,
        CryptoError::TooLong,
        CryptoError::BadLength,
        CryptoError::Forged,
        CryptoError::BadPadding,
        CryptoError::OutOfMemory,
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
            "OutOfMemory"
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
    let manifest = include_str!("../../Cargo.toml");
    let section = |name: &str| -> String {
        let start = manifest.find(name).expect("section");
        let rest = &manifest[start + name.len()..];
        let end = rest.find("\n[").unwrap_or(rest.len());
        rest[..end].to_owned()
    };
    // Comments are prose: what counts is what the manifest declares.
    let dependencies = section("[dependencies]");
    let declarations: Vec<&str> = dependencies
        .lines()
        .filter(|line| line.contains(" = ") && !line.trim_start().starts_with('#'))
        .map(str::trim)
        .collect();
    assert_eq!(declarations.len(), 2);
    for crate_name in ["libsodium-sys-stable", "zeroize"] {
        assert!(
            declarations.iter().any(|line| line.starts_with(crate_name)),
            "{crate_name}"
        );
    }
    assert!(
        !declarations
            .iter()
            .any(|line| line.contains("use-pkg-config")),
        "the feature is named in a comment that keeps it off, never enabled"
    );
    assert!(section("[dev-dependencies]").contains("proptest"));
}

/// Spec 010, R17: the clock, the file system and the network are unreachable
/// from a crate that must not touch them (AGENTS 10).
#[test]
fn s010_t26_r17_clippy_toml_disallows_clock_fs_net() {
    let clippy = include_str!("../../../../clippy.toml");
    for method in [
        "std::time::SystemTime::now",
        "std::time::Instant::now",
        "std::thread::sleep",
        "std::fs::read",
        "std::fs::write",
        "std::fs::File::open",
        "std::fs::File::create",
        "std::net::TcpStream::connect",
    ] {
        assert!(clippy.contains(method), "{method}");
    }
    assert!(clippy.contains("AGENTS 10"));
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

/// The vector loader reads the whole file and hands back the bytes the
/// vectors declare. It covers no requirement of the spec: it is the harness
/// every vector test below depends on, so it is checked on its own.
#[test]
fn vector_loader_reads_every_vector() {
    assert_eq!(vectors::count(), 19);
    let aead = vectors::load("aead_xchacha20poly1305_ietf");
    assert_eq!(aead.kind, "positive");
    assert_eq!(aead.array::<32>("key").len(), 32);
    assert_eq!(aead.bytes("plaintext").len(), 114);
    assert_eq!(aead.expected_bytes("ciphertext").len(), 130);
    let padding = vectors::load("pad_1024");
    assert_eq!(padding.number("block"), 1024);
    let rejected = vectors::load("unpad_all_zero");
    assert_eq!(rejected.kind, "negative");
    assert_eq!(rejected.expected_text("error"), "BadPadding");
}

/// Spec 010, R6: the AEAD reproduces the published vector, in both
/// directions.
#[test]
fn s010_t07_r06_aead_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("aead_xchacha20poly1305_ietf");
    let key = Secret::<32>::from_bytes(vector.array("key"));
    let nonce = Nonce(vector.array("nonce"));
    let aad = vector.bytes("aad");
    let plaintext = vector.bytes("plaintext");
    let ciphertext = vector.expected_bytes("ciphertext");
    assert_eq!(aead_encrypt(&key, &nonce, &aad, &plaintext)?, ciphertext);
    assert_eq!(aead_decrypt(&key, &nonce, &aad, &ciphertext)?, plaintext);
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
    let vector = vectors::load("stream_xchacha20");
    let key = Secret::<32>::from_bytes(vector.array("key"));
    let nonce = Nonce(vector.array("nonce"));
    let mut buffer = vector.bytes("buf");
    stream_xor(&key, &nonce, &mut buffer)?;
    assert_eq!(buffer, vector.expected_bytes("buf"));
    Ok(())
}

/// Spec 010, R12: the secret box reproduces the published vector.
#[test]
fn s010_t18_r12_secretbox_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("secretbox_easy");
    let key = Secret::<32>::from_bytes(vector.array("key"));
    let nonce = Nonce(vector.array("nonce"));
    let plaintext = vector.bytes("plaintext");
    let sealed = vector.expected_bytes("sealed");
    assert_eq!(secretbox_seal(&key, &nonce, &plaintext)?, sealed);
    assert_eq!(secretbox_open(&key, &nonce, &sealed)?, plaintext);
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
    assert_eq!(secretbox_open(&key, &nonce, &sealed)?, plaintext);

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
    assert_eq!(secretbox_open(&key, &nonce, &boxed)?, plaintext);

    assert_eq!(checked_output_len(100, 16), Ok(116));
    assert_eq!(
        checked_output_len(usize::MAX - 15, 16),
        Err(CryptoError::TooLong)
    );
    assert_eq!(checked_output_len(usize::MAX, 1), Err(CryptoError::TooLong));
    Ok(())
}

/// Spec 010, R8: the derivation reproduces its vector, and a different
/// context gives a different subkey.
#[test]
fn s010_t12_r08_kdf_known_answer() -> Result<(), CryptoError> {
    let vector = vectors::load("kdf_subkey_0");
    let key = Secret::<32>::from_bytes(vector.array("key"));
    let context = KdfContext::new(vector.array("context"));
    let expected = Secret::<32>::from_bytes(vector.expected_bytes("subkey").try_into().unwrap());
    assert!(kdf_derive(&key, &context)? == expected);

    let other = KdfContext::new(*b"pcother1");
    assert!(kdf_derive(&key, &other)? != expected);
    Ok(())
}

/// Spec 010, R9: BLAKE2b at 32 bytes, keyed and unkeyed, on their vectors.
#[test]
fn s010_t13_r09_hash_known_answer() -> Result<(), CryptoError> {
    let unkeyed = vectors::load("blake2b_256_unkeyed");
    assert_eq!(
        hash(&unkeyed.bytes("input"))?.to_vec(),
        unkeyed.expected_bytes("hash")
    );

    let keyed = vectors::load("blake2b_256_keyed");
    let key = Secret::<32>::from_bytes(keyed.array("key"));
    let expected = Secret::<32>::from_bytes(keyed.expected_bytes("hash").try_into().unwrap());
    assert!(keyed_hash(&key, &keyed.bytes("input"))? == expected);
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
        let vector = vectors::load(name);
        let seed = Secret::<32>::from_bytes(vector.array("seed"));
        let message = vector.bytes("message");
        let (public_key, secret_key) = sign_keypair_from_seed(&seed)?;
        assert!(
            public_key == PublicKey(vector.expected_bytes("pk").try_into().unwrap()),
            "{name}"
        );
        let signature = sign_detached(&secret_key, &message)?;
        assert!(
            signature == Signature(vector.expected_bytes("signature").try_into().unwrap()),
            "{name}"
        );
        verify_detached(&public_key, &message, &signature)?;
    }
    Ok(())
}

/// Spec 010, R10: verification is strict. Every malformed signature or key
/// of the negative vectors is a forgery, never an accepted message.
#[test]
fn s010_t15_r10_verify_rejects_malformed() {
    for name in [
        "signature_s_plus_l",
        "pk_identity",
        "pk_small_order",
        "pk_non_canonical",
        "r_small_order",
        "wrong_message",
        "wrong_pk",
    ] {
        let vector = vectors::load(name);
        assert_eq!(vector.kind, "negative");
        assert_eq!(vector.expected_text("error"), "Forged", "{name}");
        let public_key = PublicKey(vector.array("pk"));
        let signature = Signature(vector.array("signature"));
        assert_eq!(
            verify_detached(&public_key, &vector.bytes("message"), &signature),
            Err(CryptoError::Forged),
            "{name}"
        );
    }
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
