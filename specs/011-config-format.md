# 011 — Channel config format

Status: in review
Phase: 1
Related ADRs: 0001, 0008, 0009, 0010, 0014, 0022, 0023, 0028
Depends on: 010-primitives-wrapper, 015-test-vectors, 017-record-encoding
Blocks: 012-message-keys, 013-wire-message, 014-fingerprint, 016-fuzz-harness, 031-auth-channel-signature
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The config is the only secret of the system (`docs/spec.md` §5): whoever holds it reads the whole channel, past and future, and there is no way to take it back (ADR 0008). This spec fixes four things:

- the record a config is;
- the two forms in which it travels, a QR in the clear and a password-encrypted file;
- the 7-word password of that file, which the core draws itself (ADR 0028);
- the channel identity the config derives, which is the Ed25519 key pair of the channel (ADR 0010) and the `channel_id` the server sees (ADR 0014).

Everything is built from `core::crypto` (spec 010-primitives-wrapper) and from the record codec of spec 017-record-encoding. Message keys, the envelope and the payload belong to specs 012-message-keys and 013-wire-message: a config knows how to identify a channel, not how to write in it. The channel identity lives here, and not in 012, because `pk_ch` and `channel_id` are what a config *is* to the server, and they are fixed the moment it is created.

This spec also creates three shared pieces, because the config is the first code that needs them:

- `core::Error`, the one error type of the core boundary (`docs/spec.md` §9);
- the English BIP-39 word list, which the password uses first and spec 014-fingerprint reuses;
- the strict base64url codec, which the config QR uses first and the verification QR of spec 014 reuses.

It pays the debt spec 010 left it: `core::crypto` bounds no password length, so the maximum a `.chatcfg` file accepts is fixed here (`docs/spec.md` §5, spec 010 R14).

In plain words: a config is a short list of numbered fields: the channel key, the server address, how long messages live, a name and two version numbers. It travels either as text inside a QR code that is shown in person, or as a small file locked with a 7-word password that is spoken over another channel.

**PR slices.** This spec is larger than one pull request of 400 lines (AGENTS 14). It is implemented in four, each with its own tests green; the spec is marked `implemented` after the last one:

- (a) `Error`, the record schema, the ranges and the channel identity (R1–R4, R6–R10, R19–R21);
- (b) the URL grammar (R5);
- (c) base64url and the QR (R11, R12);
- (d) the file, the password and the word list (R13–R18, R22).

## Requirements

- R1 A config MUST be a record of spec 017-record-encoding with exactly the keys of `docs/spec.md` §5: 0 `config_version` u8, 1 `proto_version` u8, 2 `K_ch` bytes32, 3 `server_url` text, 4 `ttl_seconds` u32, 5 `created_at` u64, 6 `invite_expires_at` u64, 7 `suggested_name` text. Key 6 MUST be optional and every other key mandatory.
- R2 The config MUST be decoded with a `Reader` under `UnknownKeys::Reject`, which MUST be closed with `end()`, and every `RecordError` MUST become `Error::BadConfig`: a key out of order or repeated, an unknown key, a missing mandatory key, a value of the wrong width, text that is not UTF-8, or bytes that do not complete a field.
- R3 Decoding MUST run in this order: the size of R7; then keys 0 and 1 alone, read with a reader under `UnknownKeys::Ignore`, where a `config_version` or `proto_version` other than 1 MUST return `Error::UnsupportedVersion`; then the strict decode of R2; then the ranges of R4 and R5; then the expiry of R10; and only then any derivation. Any later version that adds a config key MUST raise `config_version`, so that a v1 client says "update the app" instead of "corrupt config".
- R4 `ttl_seconds` MUST be within 60..=2_592_000, and `suggested_name` MUST be at most 64 bytes of UTF-8 with no Cc character (U+0000..=U+001F, U+007F..=U+009F); outside those ranges the result MUST be `Error::BadConfig`.
- R5 `server_url` MUST be at most 256 bytes and MUST be `wss://` ‖ host ‖ optional `:port`, with nothing after it, now or in any later `config_version`. The host MUST be either a name of lowercase ASCII letters, digits, `-` and `.`, in labels of 1..=63 bytes totalling at most 253 bytes, with no trailing dot and a last label that is not all digits; or an IPv4 literal of four decimal numbers within 0..=255 with no leading zero. The port MUST be within 1..=65535, with no leading zero, and MUST NOT be 443. Any other text MUST return `Error::BadConfig`.
- R6 `Config` MUST expose exactly the accessors of `docs/spec.md` §9, `channel_id()`, `server_url()`, `suggested_name()` and `ttl_seconds()`, and a crate-internal `host()` that returns the host of `server_url` without the port. The host is the string the subscription signature covers (`docs/spec.md` §6, spec 031-auth-channel-signature), not the key that groups channels on one connection, which is the host and the port together.
- R7 The encoded record MUST be at most 512 bytes, and a longer one MUST return `Error::BadConfig` before any byte of it is decoded.
- R8 `sk_ch` and `pk_ch` MUST be `sign_keypair_from_seed(kdf_derive(K_ch, CHANNEL_AUTH_CONTEXT))`, and `channel_id` MUST be the first 16 bytes of `hash(CHANNEL_ID_TAG ‖ pk_ch ‖ BE32(ttl_seconds))`, held in the type `ChannelId` and compared only with `ct_eq` (`docs/spec.md` §4).
- R9 `CHANNEL_ID_TAG` MUST be the 19 ASCII bytes `privatechat/chid/v1` and `CHANNEL_AUTH_CONTEXT` the 8 ASCII bytes `chauth__`, as named constants next to the code that uses them, equal to the literals of `docs/spec.md` §4.
- R10 `parse`, `parse_qr` and `open_encrypted` MUST return `Error::InviteExpired` for an `invite_expires_at` lower than the `now` they receive. A `Config` they return MUST NOT hold `invite_expires_at`, so that a config stored after import never expires as an invitation (ADR 0028).
- R11 The QR form MUST be the base64url, with no padding, of the config record, with no prefix and no URL scheme, carried in both directions as ASCII bytes and never as a `String` (ADR 0028). `parse_qr` MUST return `Error::BadConfig` for more than 683 bytes, for a length that leaves one character over (length mod 4 = 1), for a byte outside the base64url alphabet, for padding and for final bits that are not zero, so that each config has exactly one QR text.
- R12 Base64url MUST be implemented once, in `crates/core/src/proto/base64url.rs`, as a strict codec with no padding that rejects every input R11 rejects; spec 014-fingerprint reuses it and no other module encodes or decodes base64.
- R13 The file form MUST be `"PCFG"` ‖ `config_version` u8 ‖ `salt` 16 bytes ‖ `nonce` 24 bytes ‖ `secretbox_seal(password_key(password, salt), nonce, config record)`. Opening MUST check, in this order: the magic (`Error::BadConfig`); the version byte (`Error::UnsupportedVersion` if not 1); the length within 61..=573 bytes (`Error::BadConfig`); then derive the key and open the box; then compare the header byte with key 0 of the record, and return `Error::BadConfig` if they differ; and only then decode the record by R3.
- R14 Opening a file MUST return `Error::BadPassword` whenever the secret box does not open, and MUST NOT distinguish a wrong password from a corrupted file.
- R15 Before any key is derived, a typed password MUST be at most 1 024 bytes and MUST then be canonicalised: ASCII letters lowercased, every run of characters for which `char::is_whitespace` holds (Unicode `White_Space`) replaced by one U+0020, and leading and trailing spaces removed. A password that is not UTF-8, longer than 1 024 bytes, or whose canonical form is empty or longer than 256 bytes MUST return `Error::BadPassword`, and the empty password MUST never reach `password_key`.
- R16 `export_encrypted(now)` MUST draw the password itself and return the file together with the password's canonical bytes: 7 words of the list of R17, each chosen by 11 bits drawn with `random_bytes`, as lowercase ASCII joined by one U+0020, which is 77 bits and at most 62 bytes. No public function takes a password to seal with (ADR 0028).
- R17 The word list MUST be the English BIP-39 list, embedded in `core` as 2 048 lines ending in LF, and a test MUST pin its BLAKE2b-256 digest (`crypto::hash`) to `6fefd6b6e47ee66e6bbf8ee322305deebeefb1bd9b24e8618bf126d870175bb7`. Its SHA-256, which a human or the reference script can check with common tools, is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
- R18 `export_qr` MUST write `invite_expires_at = now + 600_000` and `export_encrypted` `invite_expires_at = now + 86_400_000`, both with `checked_add` and `Error::Internal` on overflow, and they MUST NOT take an expiry as a parameter. The crate-internal `seal_file(password, salt, nonce, now)` MUST be the only code that builds a file, and `export_encrypted` MUST be a wrapper that draws `salt`, `nonce` and the password and calls it, so that vectors can seal with fixed values.
- R19 `K_ch` MUST be copied from the record straight into a `Secret<32>`, `sk_ch` and the password key MUST be `Secret<64>` and `Secret<32>`, and every buffer holding the plaintext record, the QR text or a password MUST be a `zeroize::Zeroizing<Vec<u8>>`, including the output of `secretbox_open` as soon as it is returned. These are existing secret types, so `SECRET_TYPES` gains nothing. `Config` MUST NOT implement `Clone`, `Debug` or `Display`.
- R20 `core::Error` MUST be written by hand, with no derive crate, and MUST carry exactly the variants of `docs/spec.md` §9 except `Store`, which arrives with spec 020-store-files; the variants of this spec MUST be unit variants. Every function of `proto` MUST return `core::Error`, and one crate-internal helper MUST map `CryptoError::InitFailed`, `OutOfMemory`, `TooLong` and `BadLength` to `Error::Internal`; `Forged` and `BadPadding` MUST be mapped at the call site, and `Forged` from `secretbox_open` becomes `Error::BadPassword`.
- R21 A config that fails any check MUST leave no trace: no partially built `Config` is returned, and no error carries a byte of `K_ch` or of the password.
- R22 This spec MUST add its section to the vector generator of spec 015-test-vectors (`crates/core/src/vectors/generate.rs`) and to the reference script (`scripts/reference/vectors.py`): the config records, `pk_ch` from its seed through the RFC 8032 §6 Ed25519 reference code, `channel_id`, the QR text and the word-list digests. The comparison test of spec 015 MUST pass for `011.json`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Encoded record | 0..=512 B | `BadConfig` |
| QR text | 1..=683 ASCII bytes, length mod 4 ≠ 1 | `BadConfig` |
| `.chatcfg` file | 61..=573 B | `BadConfig` |
| `server_url` | 1..=256 B, grammar of R5 | `BadConfig` |
| Host name | 1..=253 B, labels 1..=63 B | `BadConfig` |
| IPv4 number | 0..=255, no leading zero | `BadConfig` |
| Port | 1..=65535, no leading zero, not 443 | `BadConfig` |
| `ttl_seconds` | 60..=2 592 000 | `BadConfig` |
| `suggested_name` | 0..=64 B UTF-8, no Cc | `BadConfig` |
| `invite_expires_at` on import | ≥ `now` | `InviteExpired` |
| Typed password | 1..=1 024 B, UTF-8 | `BadPassword` |
| Canonical password | 1..=256 B | `BadPassword` |
| `config_version`, `proto_version` | 1 | `UnsupportedVersion` |
| `now` on export | expiry fits in u64 | `Internal` |

The file is 45 bytes of header, 16 bytes of the secret box tag and the record. The QR text of a record of 512 bytes is 683 characters. The largest valid record is well under the limit: 414 bytes with a `server_url` of 256 bytes and a name of 64.

## Interface

```
crates/core/src/error.rs                 core::Error and the CryptoError helper (R20)
crates/core/src/proto/config.rs          Config, its record, its two forms, the password
crates/core/src/proto/config/url.rs      the grammar of R5, the only URL parsing in the workspace
crates/core/src/proto/config/tests.rs    s011_* tests
crates/core/src/proto/base64url.rs       the strict codec of R12, shared with spec 014-fingerprint
crates/core/src/proto/wordlist.rs        the list of R17, shared with spec 014-fingerprint
crates/core/src/proto/bip39_english.txt  the list itself
```

```rust
pub enum Error {
    BadLength, UnsupportedVersion, WrongChannel, Expired, RetiredKey, PeerLimit,
    Replay, BadSignature, BadPayload, CounterExhausted,
    BadConfig, BadPassword, InviteExpired, ConfigMismatch, Internal,
}

pub(crate) const CHANNEL_ID_TAG: &[u8; 19] = b"privatechat/chid/v1";
pub(crate) const CHANNEL_AUTH_CONTEXT: KdfContext = KdfContext::new(*b"chauth__");

pub(crate) struct ChannelId(pub(crate) [u8; 16]);

pub struct Config { /* K_ch: Secret<32>, the fields of §5 except invite_expires_at */ }

impl Config {
    pub fn create(server_url: &str, ttl_seconds: u32, suggested_name: &str, now: u64) -> Result<Config, Error>;
    pub fn parse(bytes: &[u8], now: u64) -> Result<Config, Error>;
    pub fn parse_qr(text: &[u8], now: u64) -> Result<Config, Error>;
    pub fn open_encrypted(bytes: &[u8], password: &[u8], now: u64) -> Result<Config, Error>;
    pub fn export_qr(&self, now: u64) -> Result<Vec<u8>, Error>;
    pub fn export_encrypted(&self, now: u64) -> Result<(Vec<u8>, Vec<u8>), Error>; // (file, password)
    pub fn channel_id(&self) -> [u8; 16];
    pub fn server_url(&self) -> &str;
    pub fn suggested_name(&self) -> &str;
    pub fn ttl_seconds(&self) -> u32;

    pub(crate) fn from_parts(k_ch: Secret<32>, server_url: &str, ttl_seconds: u32, suggested_name: &str, created_at: u64) -> Result<Config, Error>;
    pub(crate) fn seal_file(&self, password: &[u8], salt: &Salt, nonce: &Nonce, now: u64) -> Result<Vec<u8>, Error>;
    pub(crate) fn seal_file_with_key(&self, key: &Secret<32>, salt: &Salt, nonce: &Nonce, now: u64) -> Result<Vec<u8>, Error>;
    pub(crate) fn open_file_with_key(bytes: &[u8], key: &Secret<32>, now: u64) -> Result<Config, Error>;
    pub(crate) fn host(&self) -> &str;
    pub(crate) fn id(&self) -> &ChannelId;
    pub(crate) fn channel_keypair(&self) -> Result<(PublicKey, Secret<64>), Error>;
}

pub(crate) fn draw_password() -> Result<Zeroizing<Vec<u8>>, Error>;
```

The exports take `now` because they write the fixed expiry of R18, and `core` never reads a clock (AGENTS 10). `from_parts` and `seal_file` exist so that the vectors can build a config and a file from fixed inputs; the public functions draw those inputs and call them. `seal_file` and `open_encrypted` derive the key with Argon2id and then call `seal_file_with_key` and `open_file_with_key`, which the file round-trip property test of spec 016-fuzz-harness uses with a fixed key, so that `cargo test` does not run Argon2id at 64 MiB hundreds of times.

## Security

- Secrets: `K_ch` (`Secret<32>`), `sk_ch` (`Secret<64>`) and the password key (`Secret<32>`). The password and the QR text are bytes; the core keeps its own copies only in zeroizing buffers, and the caller zeroizes the bytes it receives.
- `export_qr` hands `K_ch` to the UI inside the QR text, because that is what an invitation is. It crosses as bytes, never as a `String` (AGENTS 5), and it is covered by the non-retention rule of `docs/spec.md` §8: no cache, no log, no `toString`, and the QR hides itself after 60 seconds.
- A wrong password and a corrupted file share one error on purpose (R14). The secret box tag is already a perfect offline oracle (a way for an attacker to test guesses offline); a second signal would tell an attacker which of their guesses parse.
- `K_ch` does not rotate and the file is considered exposed the moment it is sent, so the password is 7 words (77 bits) with Argon2id at the interactive parameters, both fixed by `config_version = 1` (`docs/spec.md` §5). The core draws the words inside the export (R16), so no path seals a file under a weaker password, and no client needs a random source of its own.
- Canonicalisation (R15) removes nothing from the password's strength: the 7 words are lowercase ASCII separated by single spaces, so the rule only undoes what a keyboard adds, such as a capital letter, a double space or a non-breaking space. The raw password is bounded before it is read, so a pasted megabyte costs nothing.
- The magic, version and length are checked before Argon2id runs (R13), so a foreign file costs no 64 MiB derivation. The header byte is compared with the record's version before the record's own version check, so a tampered header and a real future version fail differently.
- Everything variable-length is bounded before it is parsed (R7, R11, R13), and the URL grammar of R5 is a whitelist: no percent-decoding, no Unicode host, no IPv6, no default port written out, no path. Each server therefore has exactly one `server_url`, and two members cannot hold two spellings of one server, which would split the channel with `ConfigMismatch`.
- The version is read before the strict decode (R3), so a config from a future version gets "update the app" (`UnsupportedVersion`) rather than "corrupt config" (`BadConfig`).

## Public API changes

`Config` and `Error` are the first public types of the core, exactly as `docs/spec.md` §9 lists them: `create`, `parse`, `parse_qr`, `open_encrypted`, `export_qr`, `export_encrypted`, `channel_id`, `server_url`, `suggested_name`, `ttl_seconds`, and the variants `BadPassword` (not `BadPassphrase`) and no `BadPadding`. Spec 027-core-api confirms them for the bindings of 040-uniffi.

## Test cases

- T01 (covers R1): `s011_t01_r01_parses_the_reference_config` checks `config_reference` and `config_no_invite`.
- T02 (covers R2): `s011_t02_r02_rejects_malformed_records` over a table: keys out of order, a repeated key, an unknown key 8, a missing key 2, `K_ch` of 31 bytes, `ttl_seconds` of 3 bytes, one extra byte after the record → `BadConfig`.
- T03 (covers R3): `s011_t03_r03_version_is_read_first`: `config_version` 0 and 2 and `proto_version` 2 → `UnsupportedVersion`, also when the same record carries an unknown key 8.
- T04 (covers R4): `s011_t04_r04_ttl_and_name_ranges`: 59, 2_592_001, a name of 65 bytes, a name with U+0000 and one with U+0085 → `BadConfig`; 60, 2_592_000 and a name with U+200B accepted.
- T05 (covers R5): `s011_t05_r05_url_grammar` over a table. Accepted: `wss://host`, `wss://host:9001`, `wss://1.2.3.4`, `wss://127.0.0.1:8443` and an `.onion` host of 56 characters plus the suffix. Rejected: `ws://host`, `wss://host/path`, `wss://host/`, `wss://host?q`, `wss://HOST`, `wss://host.`, `wss://host:0`, `wss://host:065`, `wss://host:443`, `wss://user@host`, `wss://[::1]`, `wss://1.2.3`, `wss://01.2.3.4`, `wss://256.1.1.1`, `wss://a.123` and a URL of 257 bytes.
- T06 (covers R6): `s011_t06_r06_accessors_and_host`: each accessor returns the field of the vector, `host()` of `wss://host:9001` is `host`, and `host` is not `pub`.
- T07 (covers R7): `s011_t07_r07_rejects_a_record_above_the_limit`: 513 bytes → `BadConfig` before decoding, even when the first bytes are a valid key 0.
- T08 (covers R8): `s011_t08_r08_channel_id_known_answer` checks the vectors `K_ch` → `pk_ch` → `channel_id`; a `ttl_seconds` that differs by one gives a different `channel_id`.
- T09 (covers R9): `s011_t09_r09_literals_and_lengths`: `CHANNEL_ID_TAG` is 19 bytes and `CHANNEL_AUTH_CONTEXT` 8, each equal byte for byte to the literal of `docs/spec.md` §4.
- T10 (covers R10): `s011_t10_r10_expired_invitation_on_every_path`: `invite_expires_at = now − 1` → `InviteExpired` through `parse`, `parse_qr` and `open_encrypted`; `now` accepted, and the `Config` returned re-exports without the old expiry.
- T11 (covers R11): `s011_t11_r11_qr_is_canonical_base64url` checks the QR bytes of the vector; `=` padding, a `+`, a `/`, non-zero final bits, a length of 5 characters and 684 bytes → `BadConfig`.
- T12 (covers R12): `s011_t12_r12_base64url_round_trip`: a proptest over 0..=512 bytes gives back the input, and every rejection of T11 is also rejected by the codec on its own.
- T13 (covers R13): `s011_t13_r13_file_order` checks `chatcfg_reference`; a wrong magic → `BadConfig`, a version byte 2 → `UnsupportedVersion`, 60 and 574 bytes → `BadConfig`, all without calling `password_key`; a record with `config_version` 2 sealed under header byte 1 → `BadConfig`.
- T14 (covers R14): `s011_t14_r14_wrong_password_and_corruption_are_one_error`: a wrong password, and one flipped byte in each of `salt`, `nonce`, the sealed record and the tag → `BadPassword`.
- T15 (covers R15): `s011_t15_r15_password_canonical_form`: `" Able\tABOUT\u{a0}\u{3000}above "` opens a file sealed with `"able about above"`; the empty password, one of spaces only, one that is not UTF-8, one of 1 025 bytes and one whose canonical form is 257 bytes → `BadPassword`.
- T16 (covers R16): `s011_t16_r16_export_draws_the_password`: the password returned is 7 list words joined by single spaces, lowercase, at most 62 bytes and canonical by R15; it opens the file returned; two exports differ; no `pub` function of `Config` takes a password to seal with.
- T17 (covers R17): `s011_t17_r17_word_list_is_pinned`: 2 048 unique lines, sorted, and the BLAKE2b-256 digest of R17.
- T18 (covers R18): `s011_t18_r18_fixed_invitation_expiry`: the QR decodes with `invite_expires_at = now + 600_000` and the file opens with `now + 86_400_000`; `now = u64::MAX` → `Internal`; `seal_file` with the fixed inputs of the vector gives `chatcfg_reference` byte for byte.
- T19 (covers R19): `s011_t19_r19_no_printable_or_lingering_secret`: the source of `config.rs` derives none of `Clone`, `Debug` or `Display`, the plaintext, QR and password buffers are `Zeroizing`, and `SECRET_TYPES` is unchanged.
- T20 (covers R20): `s011_t20_r20_error_mapping`: `InitFailed`, `OutOfMemory`, `TooLong` and `BadLength` map to `Internal`; `Forged` from the secret box maps to `BadPassword`; the enum has no `BadPassphrase`, no `BadPadding` and no `Store`.
- T21 (covers R21): `s011_t21_r21_a_rejected_config_leaves_nothing`: for every rejection above, the `Debug` of the error contains no byte of `K_ch` or of the password.
- T22 (covers R22): `s011_t22_r22_every_vector_is_checked` iterates `vectors::all("011")` and dispatches each vector by name to the checker of its test; its fallback arm fails the test, and it is the only code that loads the 011 vectors. The comparison test of spec 015 passes for `011.json`, and the reference script reproduces every `derived` value.

## Vectors

`specs/vectors/011.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. The configs are built with `from_parts` and the file with `seal_file`, from fixed inputs. The `derived` values are recomputed by the reference script of spec 015-test-vectors.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `config_reference` | positive | derived | a config with every field, its record, its QR text and its `channel_id` |
| `config_no_invite` | positive | derived | the same without key 6 |
| `channel_id_ttl_60`, `channel_id_ttl_2592000` | positive | derived | the two ends of the TTL range, same `K_ch`, different id |
| `chatcfg_reference` | positive | derived | the `PCFG` file of `config_reference` with a fixed password, salt and nonce |
| `record_key_order`, `record_unknown_key`, `record_extra_byte`, `record_kch_31_bytes` | negative | derived | each → `BadConfig` |
| `record_version_2` | negative | derived | → `UnsupportedVersion` |
| `qr_padding`, `qr_nonzero_bits`, `qr_length_mod_4` | negative | derived | → `BadConfig` |
| `mutate_magic`, `mutate_version`, `file_version_mismatch` | negative | derived | → `BadConfig`, `UnsupportedVersion`, `BadConfig` |
| `mutate_salt`, `mutate_nonce`, `mutate_sealed` | negative | derived | one byte of each region → `BadPassword` |
| `invite_expired` | negative | derived | `invite_expires_at` in the past → `InviteExpired` |

Mutation table of the file: the magic → `BadConfig`; the version byte → `UnsupportedVersion`; any byte of `salt`, `nonce` or the sealed part → `BadPassword`.

## Acceptance criterion

`cargo test -p privatechat-core s011_` green; `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny --all-features check` and `scripts/doc_lint.sh` green; the reference script reproduces `011.json`. Fuzzing the parsers of this spec belongs to spec 016-fuzz-harness and to the phase 1 exit. Non-automatable criterion: a human confirms that the URL grammar of R5 accepts every server the project intends to support, because a rejected URL is a channel nobody can create.

## Out of scope

- The message keys, the envelope, the payload and the fingerprint (specs 012-message-keys, 013-wire-message, 014-fingerprint).
- The record codec itself (spec 017-record-encoding).
- The subscription signature to the server, which uses `sk_ch` and `host()` (spec 031-auth-channel-signature).
- Storing the config, the local identity `(pk_u, sk_u)` and the duplicate-channel rule on import (specs 020-store-files and 021-channel-session).
- Showing the password and the QR, and the camera (specs 054-qr-invite and the client specs).
- Any change to `config_version`, which is a new ADR by definition (AGENTS 3).

## Open questions

None. Decided in audit F (`docs/audit-log.md`):

- 011-R2: configs stay strict (unknown keys rejected), and any new config key raises `config_version` (R3).
- 011-R5: no IPv6 literal, no explicit `:443` and no path, now or later. A self-hosted server uses its own host or subdomain, and a server reachable only over IPv6 works through a DNS name.
- 011-R15: the canonical password is at most 256 bytes; the core draws at most 62.
- The parameter and the error say `password` (`BadPassword`), as `docs/spec.md` §9 now does.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (docs/audit-log.md)
- 2026-09-24 revised after audit F (docs/audit-log.md)
