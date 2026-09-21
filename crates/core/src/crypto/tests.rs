//! Tests of spec 010 that need no cryptographic operation: the invariants of
//! the module itself (confinement of `unsafe`, initialisation, secrets,
//! randomness, redacted output) and the pins of its build.

use proptest::prelude::{any, proptest};
use zeroize::Zeroize;

use super::{
    CryptoError, KdfContext, Nonce, PublicKey, SECRET_TYPES, Salt, Secret, Signature, ct_eq, init,
    init_calls, random_bytes, version,
};

/// Every `.rs` file of the crate. `core` does no I/O (AGENTS 10), so the test
/// cannot walk the directory: a new file is added to this list by hand.
const SOURCES: [(&str, &str); 5] = [
    ("lib.rs", include_str!("../lib.rs")),
    ("crypto.rs", include_str!("../crypto.rs")),
    ("crypto/ffi.rs", include_str!("ffi.rs")),
    ("crypto/secret.rs", include_str!("secret.rs")),
    ("crypto/tests.rs", include_str!("tests.rs")),
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
