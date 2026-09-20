//! Nucli del xat privat E2E: criptografia, format de cable, sessió.
//!
//! Aquest crate no fa I/O ni llegeix el rellotge: rep bytes i un `now`, i torna
//! bytes i esdeveniments (`docs/spec.md` §9). L'esquelet d'aquest fitxer el crea
//! la spec 000; el contingut arriba amb les specs 010–028.

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

/// Servidor d'intercanvi per defecte de la instal·lació (`docs/spec.md` §8, ADR 0022).
///
/// És l'única URL de servidor al codi. Cada *fork* hi posa la seva; el valor
/// definitiu del projecte es fixa quan hi hagi domini (§12). `server.invalid`
/// és un nom reservat que no resol mai (RFC 2606), així que un build sense
/// configurar no pot connectar a cap lloc per error.
pub const DEFAULT_SERVER_URL: &str = "wss://server.invalid";

#[cfg(test)]
mod tests {
    use super::DEFAULT_SERVER_URL;

    /// Spec 000, R4: la URL per defecte és `wss://` i, fins que hi hagi domini,
    /// apunta al TLD reservat `.invalid`.
    #[test]
    fn s000_t04_r04_default_server_url_is_wss_placeholder() {
        assert!(DEFAULT_SERVER_URL.starts_with("wss://"));
        assert!(DEFAULT_SERVER_URL.ends_with(".invalid"));
    }

    /// Spec 000, R3: els lints del workspace deneguen `unwrap` i companyia.
    /// Es comprova llegint el `Cargo.toml` del workspace, que és la font única.
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

    /// Spec 000, R7: la toolchain està fixada a una versió estable concreta.
    #[test]
    fn s000_t07_r07_toolchain_is_pinned() {
        let toolchain = include_str!("../../rust-toolchain.toml");
        assert!(toolchain.contains("channel = \"1.98.1\""));
        assert!(toolchain.contains("\"rustfmt\"") && toolchain.contains("\"clippy\""));
    }

    /// Spec 000, R8: `deny.toml` prohibeix els crates criptogràfics i de compressió.
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
