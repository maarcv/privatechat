//! Core of the private E2E chat: cryptography, wire format, session.
//!
//! This crate does no I/O and never reads a clock: it takes bytes and a `now`
//! and returns bytes and events (`docs/spec.md` §9). Spec 000 creates this
//! skeleton; the contents arrive with specs 010–028.

#![forbid(unsafe_code)]
// Es relaxarà a `deny` només quan existeixi `crypto/ffi.rs` (AGENTS 12).
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

    /// Spec 000, R3: the workspace lints deny `unwrap` and friends.
    /// Checked by reading the workspace `Cargo.toml`, which is the single source.
    #[test]
    fn s000_t03_r03_workspace_lints_deny_unwrap_and_arithmetic() {
        let manifest = include_str!("../../Cargo.toml");
        for lint in [
            "unwrap_used = \"deny\"",
            "expect_used = \"deny\"",
            "panic = \"deny\"",
            "indexing_slicing = \"deny\"",
            "arithmetic_side_effects = \"deny\"",
        ] {
            assert!(manifest.contains(lint), "missing workspace lint: {lint}");
        }
        assert!(manifest.contains("overflow-checks = true"));
    }

    /// Spec 000, R7: the toolchain is pinned to one concrete stable version.
    #[test]
    fn s000_t07_r07_toolchain_is_pinned() {
        let toolchain = include_str!("../../rust-toolchain.toml");
        assert!(toolchain.contains("channel = \"1.98.1\""));
        assert!(toolchain.contains("\"rustfmt\"") && toolchain.contains("\"clippy\""));
    }

    /// Spec 000, R8: `deny.toml` bans cryptographic and compression crates.
    #[test]
    fn s000_t08_r08_deny_bans_crypto_crates() {
        let deny = include_str!("../../deny.toml");
        for crate_name in [
            "ring",
            "openssl",
            "ed25519-dalek",
            "argon2",
            "sodiumoxide",
            "flate2",
            "zstd",
        ] {
            assert!(
                deny.contains(&format!("crate = \"{crate_name}\"")),
                "deny.toml must ban {crate_name}"
            );
        }
        assert!(
            deny.contains("allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]")
        );
    }
}
