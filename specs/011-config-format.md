# 011 — Channel config format

Status: in review
Phase: 1
Related ADRs: 0001, 0008, 0009, 0010, 0014, 0022
Depends on: 010-primitives-wrapper
Blocks: 012-message-keys, 013-wire-message, 014-fingerprint, 031-auth-channel-signature
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The config is the only secret of the system (`docs/spec.md` §5): whoever holds it reads the whole channel, past and future, and there is no way to take it back (ADR 0008). This spec fixes three things: the document a config is, the two forms in which it travels — a QR in the clear and an encrypted file — and the channel identity it derives, which is the Ed25519 key pair of the channel (ADR 0010) and the `channel_id` the server sees (ADR 0014).

Everything is built from `core::crypto` (spec 010-primitives-wrapper) and nothing else. Message keys, envelope and payload belong to specs 012-message-keys and 013-wire-message: a config knows how to identify a channel, not how to write in it. The channel identity lives here, and not in 012, because `pk_ch` and `channel_id` are properties of the config itself: they are what a config *is* to the server, and they are fixed the moment it is created.

This spec also pays the debt spec 010 left it: `core::crypto` bounds no password length, so the maximum a `.chatcfg` file accepts is fixed here (`docs/spec.md` §5, spec 010 R14).

## Requirements

- R1 A config MUST be a CBOR map carrying the integer keys of `docs/spec.md` §5 and no others: 0 `config_version` uint, 1 `proto_version` uint, 2 `K_ch` 32 bytes, 3 `server_url` text, 4 `ttl_seconds` uint, 5 `created_at` uint, 6 `invite_expires_at` uint or absent, 7 `suggested_name` text.
- R2 Decoding MUST go through `ciborium` into a `struct` with `serde` and `recursion_limit = 8`, MUST NOT build a generic CBOR value, and MUST return `Error::BadConfig` for a duplicate key, an unknown key, a missing key other than 6, a value of the wrong CBOR major type, a value that does not fit its type, or any trailing byte after the map.
- R3 `config_version` and `proto_version` MUST both be 1; any other value MUST return `Error::UnsupportedVersion` before any other check of the document.
- R4 `ttl_seconds` MUST be within 60..=2_592_000 and `suggested_name` at most 64 bytes of UTF-8 with no character of the Unicode categories Cc and Cf; outside those ranges MUST return `Error::BadConfig`.
- R5 `server_url` MUST be at most 256 bytes and MUST match `wss://` ‖ host ‖ optional `:port`, with nothing after it: a host of lowercase ASCII letters, digits, `-` and `.` in labels of 1..=63 bytes totalling at most 253 bytes with no trailing dot, or an IPv4 literal, or an IPv6 literal between brackets; a port of 1..=65535 with no leading zero. Any other text MUST return `Error::BadConfig`.
- R6 `Config::host()` MUST return the host of `server_url` without brackets and without the port, which is the string the subscription signature covers (`docs/spec.md` §6).
- R7 The serialised config MUST be at most 512 bytes, and a document above that MUST return `Error::BadConfig` before it is decoded.
- R8 `sk_ch` and `pk_ch` MUST be `sign_keypair_from_seed(kdf_derive(K_ch, "chauth__"))`, and `channel_id` MUST be the first 16 bytes of `hash("privatechat/chid/v1" ‖ pk_ch ‖ BE32(ttl_seconds))` (`docs/spec.md` §4).
- R9 `Config::create` MUST generate `K_ch` with `random_bytes`, set `config_version` and `proto_version` to 1, `created_at` to the `now` it receives and no `invite_expires_at`, and MUST validate `server_url`, `ttl_seconds` and `suggested_name` by the rules of R4 and R5.
- R10 `Config::parse` MUST reject a config whose `invite_expires_at` is present and lower than the `now` it receives, with `Error::InviteExpired`, after the checks of R2 to R7 and before deriving anything.
- R11 The QR form MUST be the CBOR of the config with no prefix and no URL scheme, so that no system camera opens it as a link (`docs/spec.md` §5).
- R12 The file form MUST be `"PCFG"` ‖ `config_version` uint8 ‖ `salt` 16 bytes ‖ `nonce` 24 bytes ‖ `secretbox_seal(password_key(password, salt), nonce, config_cbor)`, with `salt` and `nonce` from `random_bytes`; a file whose first 4 bytes are not `PCFG` MUST return `Error::BadConfig`, and one whose `config_version` is not 1 MUST return `Error::UnsupportedVersion`.
- R13 Opening a file MUST return `Error::BadPassphrase` when the secret box does not open, and MUST NOT distinguish a wrong password from a corrupted file.
- R14 The password of a file MUST be within 1..=256 bytes; outside that range MUST return `Error::BadPassphrase`, and the empty password MUST never reach `password_key`.
- R15 `Config::export_encrypted` MUST refuse an `invite_expires_at` more than 86_400_000 milliseconds after the `now` it receives, and the QR export MUST refuse one more than 86_400_000 milliseconds after it, both with `Error::BadConfig`.
- R16 `K_ch`, `sk_ch` and the key derived from the password MUST live in `Secret<32>` and `Secret<64>`, MUST be added to `SECRET_TYPES`, and `Config` MUST NOT implement `Clone`, `Debug`, `Display` or any `serde` trait that would print or copy it.
- R17 `core` MUST gain exactly two dependencies, `ciborium` and `serde` with the feature `derive`, both with `default-features = false`; the manifest test of spec 010-primitives-wrapper MUST be updated in the same pull request and `cargo deny --all-features check` MUST pass.
- R18 A config that fails any check of this spec MUST leave no trace: no `Store` commit, no partially built `Config`, and no error carrying a byte of `K_ch` or of the password.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Serialised config | 0..=512 B | `BadConfig` |
| `server_url` | 1..=256 B, grammar of R5 | `BadConfig` |
| Host of `server_url` | 1..=253 B, labels 1..=63 B | `BadConfig` |
| Port | 1..=65535, no leading zero | `BadConfig` |
| `ttl_seconds` | 60..=2 592 000 | `BadConfig` |
| `suggested_name` | 0..=64 B UTF-8, no Cc, no Cf | `BadConfig` |
| `invite_expires_at` on export | `now`..=`now + 86 400 000` | `BadConfig` |
| `password` | 1..=256 B | `BadPassphrase` |
| `.chatcfg` file | 61..=573 B | `BadConfig` |
| `config_version`, `proto_version` | 1 | `UnsupportedVersion` |

The file is the 45 fixed bytes of its header plus the 16 of the secret box mac plus the config.

## Interface

```
crates/core/src/config.rs              Config, its parser and its two forms
crates/core/src/config/url.rs          the grammar of R5, which is the only URL parsing in the workspace
crates/core/src/config/tests.rs        s011_* tests
```

```rust
pub struct Config { /* K_ch: Secret<32>, and the fields of §5 */ }

impl Config {
    pub fn create(server_url: &str, ttl_seconds: u32, suggested_name: &str, now: u64) -> Result<Config, Error>;
    pub fn parse(bytes: &[u8], now: u64) -> Result<Config, Error>;
    pub fn open_encrypted(bytes: &[u8], password: &[u8], now: u64) -> Result<Config, Error>;
    pub fn export_qr(&self, invite_expires_at: Option<u64>, now: u64) -> Result<Vec<u8>, Error>;
    pub fn export_encrypted(&self, password: &[u8], invite_expires_at: Option<u64>, now: u64) -> Result<Vec<u8>, Error>;
    pub fn channel_id(&self) -> [u8; 16];
    pub fn host(&self) -> &str;
    pub(crate) fn channel_keypair(&self) -> Result<(PublicKey, Secret<64>), CryptoError>;
}
```

The exported forms take `now` because both refuse an expiry beyond the window of R15, and `core` never reads a clock (AGENTS 10).

## Security

- Secrets: `K_ch` (`Secret<32>`), `sk_ch` (`Secret<64>`) and the password key (`Secret<32>`). The password itself is bytes the caller owns and zeroizes; the core never copies it into a `String`.
- The two error paths a holder of a file can observe, a wrong password and a corrupted file, share one variant on purpose (R13): the secret box tag is already a perfect offline oracle, and a second signal would tell an attacker which of their guesses parse.
- `K_ch` does not rotate and the file is considered exposed the moment it is sent, so the password is 7 BIP-39 words (77 bits) with Argon2id at the interactive parameters, both fixed by `config_version = 1` (`docs/spec.md` §5).
- The QR carries the config in the clear: whoever photographs the screen has the channel. The UI measures of §8 (no screenshot, no sharing, hidden after 60 seconds) are not this spec's, but the format is what makes them necessary.
- Everything variable-length is bounded before it is parsed (R7), and the URL grammar of R5 is a whitelist: no percent-decoding, no Unicode host, no normalisation that could make two configs look different and hash the same.

## Public API changes

`Config` is the first public type of the core: `create`, `parse`, `open_encrypted`, `export_qr`, `export_encrypted`, `channel_id` and `host`. `docs/spec.md` §9 lists `export_encrypted` without `now`; this spec adds it, so spec 027-core-api and the bindings of 040-uniffi take the signature above.

## Test cases

- T01 (covers R1, R2): `s011_t01_r01_parses_the_reference_config` on the positive vector; `s011_t02_r02_rejects_malformed_cbor` over a table of documents — duplicate key, unknown key, missing key 2, `K_ch` of 31 bytes, `ttl_seconds` as text, one trailing byte — each `BadConfig`.
- T03 (covers R3): `s011_t03_r03_rejects_other_versions`: `config_version` 0 and 2, `proto_version` 2 → `UnsupportedVersion`.
- T04 (covers R4): `s011_t04_r04_rejects_ttl_and_name_out_of_range`: 59, 2_592_001, a name of 65 bytes and a name with U+0000 → `BadConfig`; 60 and 2_592_000 accepted.
- T05 (covers R5, R6): `s011_t05_r05_url_grammar` over a table of accepted and rejected URLs, including `wss://host`, `wss://host:443`, `wss://1.2.3.4`, `wss://[::1]:9001`, a 56-character `.onion`, and the rejections `ws://host`, `wss://host/path`, `wss://host?q`, `wss://HOST`, `wss://host.`, `wss://host:0`, `wss://host:065`, `wss://user@host` and a URL of 257 bytes; `s011_t06_r06_host_has_no_brackets_or_port` checks `host()` for the IPv6 and the port cases.
- T07 (covers R7): `s011_t07_r07_rejects_a_document_above_the_limit`: 513 bytes → `BadConfig`, and the check happens before decoding.
- T08 (covers R8): `s011_t08_r08_channel_id_known_answer` on the vector: `K_ch` → `pk_ch` → `channel_id`; a `ttl_seconds` changed by one gives a different `channel_id`.
- T09 (covers R9): `s011_t09_r09_create_fills_the_fixed_fields`: two calls give different `K_ch`, versions are 1, `created_at` is the `now` passed and there is no `invite_expires_at`.
- T10 (covers R10): `s011_t10_r10_rejects_an_expired_invitation`: `invite_expires_at` = `now − 1` → `InviteExpired`; `now` accepted.
- T11 (covers R11): `s011_t11_r11_qr_is_bare_cbor`: the QR bytes decode as the config and start with a CBOR map header, and carry no `:` in their first 16 bytes.
- T12 (covers R12, R13): `s011_t12_r12_file_round_trip` on the vector; `s011_t13_r12_rejects_a_foreign_file`: a wrong magic → `BadConfig`, `config_version` 2 → `UnsupportedVersion`; `s011_t14_r13_wrong_password_and_corruption_are_one_error`: a wrong password and every single-byte mutation of the sealed part → `BadPassphrase`.
- T15 (covers R14): `s011_t15_r14_password_length`: empty and 257 bytes → `BadPassphrase`; 1 and 256 bytes accepted.
- T16 (covers R15): `s011_t16_r15_invitation_window`: `now + 86_400_001` → `BadConfig` for both export forms; `now + 86_400_000` accepted.
- T17 (covers R16): `s011_t17_r16_config_holds_no_printable_secret`: the source of `config.rs` derives none of the forbidden traits, and `SECRET_TYPES` lists the types this spec adds.
- T18 (covers R17): `s011_t18_r17_manifest_pins_dependencies`: the manifest declares exactly `libsodium-sys-stable`, `zeroize`, `ciborium` and `serde`, none with default features beyond what this requirement allows.
- T19 (covers R18): `s011_t19_r18_a_rejected_config_leaves_nothing`: for every rejection above, the `Store` receives no commit and the error's `Debug` contains no byte of `K_ch` or of the password.

## Vectors

`specs/vectors/011.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by the core once this spec is implemented, and from then on frozen (AGENTS 18).

| name | kind | source | origin |
| --- | --- | --- | --- |
| `config_reference` | positive | derived | a config with all fields, its CBOR and its `channel_id` |
| `config_no_invite` | positive | derived | the same without key 6 |
| `channel_id_ttl_60`, `channel_id_ttl_2592000` | positive | derived | the two ends of the TTL range, same `K_ch`, different id |
| `chatcfg_reference` | positive | derived | the `PCFG` file of `config_reference` with a fixed password, salt and nonce |
| `mutate_cbor_duplicate_key`, `mutate_cbor_unknown_key`, `mutate_cbor_trailing_byte`, `mutate_kch_31_bytes` | negative | derived | each → `BadConfig` |
| `mutate_magic`, `mutate_file_version` | negative | derived | → `BadConfig` and `UnsupportedVersion` |
| `mutate_sealed_byte` | negative | derived | one byte of the secret box → `BadPassphrase` |
| `invite_expired` | negative | derived | `invite_expires_at` in the past → `InviteExpired` |

Mutation table of the file: any byte of `salt`, `nonce` or the sealed part → `BadPassphrase`; the magic → `BadConfig`; the version byte → `UnsupportedVersion`. Every negative vector asserts `commits = 0`.

## Acceptance criterion

`cargo test -p privatechat-core s011_` green; `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny --all-features check` and `scripts/doc_lint.sh` green. Non-automatable criterion: a human confirms that the URL grammar of R5 accepts every server the project intends to support, because a rejected URL is a channel nobody can create.

## Out of scope

- The message keys, the envelope, the payload and the fingerprint (specs 012-message-keys, 013-wire-message, 014-fingerprint).
- The subscription signature to the server, which uses `sk_ch` (spec 031-auth-channel-signature).
- Storing the config, the local identity `(pk_u, sk_u)` and the duplicate-channel rule on import (specs 020-store-files and 021-channel-session).
- Generating the 7 BIP-39 words: the word list arrives with spec 014-fingerprint, which needs it for the 12 words, and the UI asks for it.
- Any change to `config_version`, which is a new ADR by definition (AGENTS 3).

## Open questions

- [ ] 011-R2: an unknown key is an error here, while an unknown key in the payload is ignored so that v1.x can add fields (`docs/spec.md` §4). The asymmetry is deliberate — a config with a field we do not understand is a config we cannot honour — but it means a v1.1 config cannot be read by a v1.0 client even when the new field is optional. Confirm, or make unknown keys ignored and rely on `config_version` alone.
- [ ] 011-R5: the maximum of 256 bytes for `server_url` and the whitelist grammar are this spec's, not `docs/spec.md`'s. They exclude a Unicode host and any path, which no current use needs. Confirm both numbers.
- [ ] 011-R14: the maximum of 256 bytes for the password is this spec's. The app generates 7 BIP-39 words, at most 62 bytes, so the margin is for a password typed or pasted by hand in a future version. Confirm.
- [ ] 011-R17: `ciborium` and `serde` are the third and fourth dependencies of `core` and the first that parse untrusted input. `serde` is unavoidable with `ciborium`; the pair is justified because writing a CBOR decoder by hand would be a larger attack surface than the one it removes. Confirm, and confirm that the fuzz target of spec 016-fuzz-harness covers `Config::parse` from the first day.
- [ ] 011: `docs/spec.md` §9 names the parameter `passphrase` while §5 and this spec say `password`. The rename is a pending decision of audit D; this spec assumes `password` and spec 027-core-api settles it.

## History

- 2026-09-21 in review
