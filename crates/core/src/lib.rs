//! Core of the private E2E chat: cryptography, wire format, session.
//!
//! This crate does no I/O and never reads a clock: it takes bytes and a `now`
//! and returns bytes and events (`docs/spec.md` §9). Spec 000 creates this
//! skeleton; the contents arrive with specs 010–028.

// `deny`, not `forbid`: `crypto/ffi.rs` alone will `allow` it (AGENTS 12).
#![deny(unsafe_code)]
// Tests may relax these four lints to build fixtures; production code never does (AGENTS 4).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

#[allow(dead_code, reason = "reached through proto, spec 027-core-api")]
mod crypto;

mod error;

#[cfg(any(test, fuzzing))]
pub mod fuzz_entry;

#[allow(dead_code, reason = "reached through Device, spec 027-core-api")]
mod proto;

#[cfg(test)]
mod vectors;

pub use error::Error;
pub use proto::config::Config;
pub use proto::fingerprint::Fingerprint;

/// Default exchange server of a fresh installation (`docs/spec.md` §8, ADR 0022).
///
/// This is the only server URL in the code. Each fork sets its own; the
/// project's final value is fixed once there is a domain (§12).
/// `server.invalid` is a reserved name that never resolves (RFC 2606), so an
/// unconfigured build cannot connect anywhere by mistake.
pub const DEFAULT_SERVER_URL: &str = "wss://server.invalid";

#[cfg(test)]
mod tests {
    use super::DEFAULT_SERVER_URL;

    /// The code lines of one `[section]` of a TOML file, comments and blank
    /// lines dropped, so that a commented-out copy of a line never counts.
    fn section<'a>(toml: &'a str, header: &str) -> Vec<&'a str> {
        let mut lines = Vec::new();
        let mut inside = false;
        for line in toml.lines() {
            // A trailing comment is prose too.
            let line = line.split(" #").next().unwrap_or(line).trim();
            // `[[array]]` opens a table too and so closes the section.
            if line.starts_with('[') {
                inside = line == header;
                continue;
            }
            if inside && !line.is_empty() && !line.starts_with('#') {
                lines.push(line);
            }
        }
        lines
    }

    /// Whether a Rust source holds `attribute` as a line of its own, not in a
    /// comment.
    fn has_line(source: &str, attribute: &str) -> bool {
        source.lines().any(|line| line.trim() == attribute)
    }

    /// Spec 000, R4: the default URL is the reserved `.invalid` placeholder
    /// until there is a domain.
    #[test]
    fn s000_t04_r04_default_server_url_is_wss_placeholder() {
        assert_eq!(DEFAULT_SERVER_URL, "wss://server.invalid");
    }

    /// Spec 000, R3: the workspace lints deny `unwrap` and friends, every
    /// crate takes them, `unsafe` is denied in the workspace and in `core` and
    /// forbidden in `store` and `server`, and release builds check overflow.
    /// Each line is read in its own section and never from a comment.
    #[test]
    fn s000_t03_r03_workspace_lints_deny_unwrap_and_arithmetic() {
        let manifest = include_str!("../../../Cargo.toml");
        let clippy = section(manifest, "[workspace.lints.clippy]");
        for lint in [
            "arithmetic_side_effects",
            "cast_possible_truncation",
            "cast_sign_loss",
            "dbg_macro",
            "expect_used",
            "indexing_slicing",
            "panic",
            "print_stderr",
            "print_stdout",
            "todo",
            "undocumented_unsafe_blocks",
            "unimplemented",
            "unreachable",
            "unwrap_used",
        ] {
            let line = format!("{lint} = \"deny\"");
            assert!(
                clippy.contains(&line.as_str()),
                "missing workspace lint: {line}"
            );
        }
        let rust = section(manifest, "[workspace.lints.rust]");
        assert!(rust.contains(&"unsafe_code = \"deny\""));
        assert!(section(manifest, "[profile.release]").contains(&"overflow-checks = true"));
        for crate_manifest in [
            include_str!("../Cargo.toml"),
            include_str!("../../store/Cargo.toml"),
            include_str!("../../server/Cargo.toml"),
        ] {
            assert_eq!(section(crate_manifest, "[lints]"), ["workspace = true"]);
        }
        assert!(has_line(include_str!("lib.rs"), "#![deny(unsafe_code)]"));
        for crate_root in [
            include_str!("../../store/src/lib.rs"),
            include_str!("../../server/src/main.rs"),
        ] {
            assert!(has_line(crate_root, "#![forbid(unsafe_code)]"));
        }
    }

    /// Spec 000, R7: the toolchain is pinned to one concrete stable version
    /// with its two components, and the workspace is on edition 2024.
    #[test]
    fn s000_t07_r07_toolchain_is_pinned() {
        let toolchain = section(include_str!("../../../rust-toolchain.toml"), "[toolchain]");
        assert!(toolchain.contains(&"channel = \"1.98.1\""));
        assert!(toolchain.contains(&"components = [\"rustfmt\", \"clippy\"]"));
        let manifest = include_str!("../../../Cargo.toml");
        assert!(section(manifest, "[workspace.package]").contains(&"edition = \"2024\""));
    }

    /// Spec 000, R8: `deny.toml` bans every cryptographic and compression
    /// crate outright, lets the ones with wrappers in only under exactly those
    /// wrappers, allows exactly the listed licences, and refuses unknown
    /// sources, yanked crates and wildcard versions.
    #[test]
    fn s000_t08_r08_deny_bans_crypto_crates() {
        let deny = include_str!("../../../deny.toml");
        // Only the entries of `deny = [ … ]`: a crate under `skip` is not banned.
        let bans: Vec<&str> = section(deny, "[bans]")
            .into_iter()
            .skip_while(|line| *line != "deny = [")
            .skip(1)
            .take_while(|line| *line != "]")
            .filter(|line| line.starts_with("{ crate = "))
            .collect();
        let entry = |name: &str| {
            let prefix = format!("{{ crate = \"{name}\"");
            bans.iter().copied().find(|line| {
                line.starts_with(&format!("{prefix} ")) || line.starts_with(&format!("{prefix},"))
            })
        };
        for crate_name in [
            "sha2",
            "sha3",
            "blake2",
            "md-5",
            "aes",
            "aes-gcm",
            "chacha20",
            "chacha20poly1305",
            "ed25519-dalek",
            "x25519-dalek",
            "curve25519-dalek",
            "argon2",
            "hkdf",
            "hmac",
            "ring",
            "sodiumoxide",
            "openssl",
            "openssl-sys",
            "zstd",
            "brotli",
            "lz4",
        ] {
            let line = entry(crate_name).expect("deny.toml bans every crate of the list");
            assert!(
                !line.contains("wrappers"),
                "{crate_name} is banned outright: {line}"
            );
        }
        // The wrapped bans, each with exactly the wrappers AGENTS 2 and 24 allow.
        for (crate_name, wrappers) in [
            ("rand", r#"["proptest", "rand_chacha", "rand_xorshift"]"#),
            ("rand_chacha", r#"["proptest", "rand"]"#),
            ("rand_xorshift", r#"["proptest"]"#),
            (
                "rand_core",
                r#"["proptest", "rand", "rand_chacha", "rand_xorshift"]"#,
            ),
            ("getrandom", r#"["rand_core", "tempfile"]"#),
            ("fastrand", r#"["tempfile"]"#),
            ("tempfile", r#"["proptest", "rusty-fork"]"#),
            ("rusty-fork", r#"["proptest"]"#),
            ("minisign-verify", r#"["libsodium-sys-stable"]"#),
            ("flate2", r#"["zip"]"#),
            ("zlib-rs", r#"["flate2"]"#),
            ("zip", r#"["libsodium-sys-stable"]"#),
            ("zopfli", r#"["zip"]"#),
            ("libflate", r#"["libsodium-sys-stable"]"#),
            ("libflate_lz77", r#"["libflate"]"#),
        ] {
            let line = format!("{{ crate = \"{crate_name}\", wrappers = {wrappers} }},");
            assert_eq!(entry(crate_name), Some(line.as_str()), "{crate_name}");
        }
        let wrapped = bans.iter().filter(|line| line.contains("wrappers")).count();
        assert_eq!(wrapped, 15, "a ban gained wrappers the test does not name");
        // Whole sections, so that an added exception or source fails too.
        assert_eq!(
            section(deny, "[licenses]"),
            [
                "version = 2",
                "allow = [",
                "\"MIT\",",
                "\"Apache-2.0\",",
                "\"Apache-2.0 WITH LLVM-exception\",",
                "\"BSD-2-Clause\",",
                "\"BSD-3-Clause\",",
                "\"ISC\",",
                "\"Unicode-3.0\",",
                "\"Zlib\",",
                "\"MPL-2.0\",",
                "]",
                "confidence-threshold = 0.9",
            ]
        );
        assert_eq!(
            section(deny, "[sources]"),
            [
                "unknown-registry = \"deny\"",
                "unknown-git = \"deny\"",
                "allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]",
            ]
        );
        assert!(section(deny, "[advisories]").contains(&"yanked = \"deny\""));
        assert!(section(deny, "[bans]").contains(&"wildcards = \"deny\""));
    }
}
