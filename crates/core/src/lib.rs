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

// The callers of `crypto` arrive with specs 011-014; until then every item of
// the module is reachable only from its own tests.
#[allow(dead_code, unused_imports)]
mod crypto;

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

    /// Spec 000, R4: the default URL is `wss://` and, until there is a domain,
    /// points at the reserved `.invalid` TLD.
    #[test]
    fn s000_t04_r04_default_server_url_is_wss_placeholder() {
        assert!(DEFAULT_SERVER_URL.starts_with("wss://"));
        assert!(DEFAULT_SERVER_URL.ends_with(".invalid"));
    }

    /// Spec 000, R3: the workspace lints deny `unwrap` and friends, `unsafe`
    /// is denied in the workspace and forbidden in `store` and `server`.
    /// Checked by reading the workspace `Cargo.toml`, which is the single source.
    #[test]
    fn s000_t03_r03_workspace_lints_deny_unwrap_and_arithmetic() {
        let manifest = include_str!("../../../Cargo.toml");
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
            assert!(manifest.contains(&line), "missing workspace lint: {line}");
        }
        assert!(manifest.contains("unsafe_code = \"deny\""));
        assert!(manifest.contains("overflow-checks = true"));
        for crate_root in [
            include_str!("../../store/src/lib.rs"),
            include_str!("../../server/src/main.rs"),
        ] {
            assert!(crate_root.contains("#![forbid(unsafe_code)]"));
        }
    }

    /// Spec 000, R7: the toolchain is pinned to one concrete stable version.
    #[test]
    fn s000_t07_r07_toolchain_is_pinned() {
        let toolchain = include_str!("../../../rust-toolchain.toml");
        assert!(toolchain.contains("channel = \"1.98.1\""));
        assert!(toolchain.contains("\"rustfmt\"") && toolchain.contains("\"clippy\""));
    }

    /// Spec 000, R8: `deny.toml` bans every cryptographic and compression
    /// crate, lets `rand` in only under `proptest`, and allows exactly the
    /// listed licences.
    #[test]
    fn s000_t08_r08_deny_bans_crypto_crates() {
        let deny = include_str!("../../../deny.toml");
        for crate_name in [
            "rand",
            "rand_core",
            "getrandom",
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
            "openssl",
            "openssl-sys",
            "sodiumoxide",
            "flate2",
            "zstd",
            "brotli",
            "lz4",
        ] {
            assert!(
                deny.contains(&format!("{{ crate = \"{crate_name}\"")),
                "deny.toml must ban {crate_name}"
            );
        }
        assert!(deny.contains("{ crate = \"rand\", wrappers = [\"proptest\""));
        for licence in [
            "MIT",
            "Apache-2.0",
            "Apache-2.0 WITH LLVM-exception",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Unicode-3.0",
            "Zlib",
            "MPL-2.0",
        ] {
            assert!(
                deny.contains(&format!("  \"{licence}\",\n")),
                "deny.toml must allow the licence {licence}"
            );
        }
        assert!(
            deny.contains("allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]")
        );
    }
}
