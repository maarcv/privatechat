# 010 — Primitives wrapper

Status: in review
Phase: 1
Related ADRs: 0002, 0005, 0012
Depends on: 000, 001
Blocks: 011, 012, 013, 014, 015, 016
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Everything cryptographic in the project comes from libsodium (`docs/spec.md` §4 "Primitives", ADR 0002) through one module, `core::crypto`, which is the only code allowed to hold key material, call `unsafe` or compare fixed-size bytes (AGENTS 2, 5, 12, 22). This spec defines that module: typed, safe wrappers over exactly the primitives §4 lists, the `Secret<N>` type, constant-time equality, and nothing protocol-specific. Domain tags, KDF contexts, the key hierarchy and the envelope arrive with specs 011–014 and are built only from what is defined here.

## Requirements

- R1 `crates/core/src/crypto` MUST be the only module of the workspace that depends on `libsodium-sys-stable`, and `crates/core/src/crypto/ffi.rs` the only file containing the token `unsafe`; `ffi.rs` MUST carry `#![allow(unsafe_code)]`, `#![deny(unsafe_op_in_unsafe_fn)]` and a `// SAFETY:` comment on every `unsafe` block.
- R2 `sodium_init()` MUST be called at most once per process through `std::sync::OnceLock` before any other libsodium call; a return value of −1 MUST surface as `CryptoError::InitFailed` from the function being called, never as a panic.
- R3 `Secret<const N: usize>` MUST wrap `[u8; N]`, derive `Zeroize` and `ZeroizeOnDrop`, implement `Debug` as the literal `[REDACTED]` and `PartialEq` through `ct_eq`, and MUST NOT implement `Clone`, `Copy`, `Default`, `Display`, `Hash`, `Ord`, `PartialOrd`, `AsRef<[u8]>`, `Deref` or `serde` traits; its bytes are reachable only through `pub(crate) fn expose(&self) -> &[u8; N]`. In this spec the only instantiations are `Secret<32>` and `Secret<64>`, and both are listed in `SECRET_TYPES`.
- R4 `ct_eq(a: &[u8; N], b: &[u8; N]) -> bool` MUST call `sodium_memcmp` and MUST be the only equality used on fixed-size byte arrays anywhere in `core`.
- R5 `random_bytes::<N>() -> [u8; N]` and `Secret::<N>::random()` MUST use `randombytes_buf` and MUST be the only randomness source in `core`.
- R6 `aead_encrypt(key: &Secret<32>, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>` MUST return `crypto_aead_xchacha20poly1305_ietf` ciphertext followed by its 16-byte tag (output length = input length + 16); `aead_decrypt` with the same arguments MUST return the plaintext, or `CryptoError::Forged` when the tag does not verify, including any single-byte change to ciphertext, tag, `aad` or nonce.
- R7 `stream_xor(key: &Secret<32>, nonce: &Nonce, buf: &mut [u8]) -> Result<(), CryptoError>` MUST apply `crypto_stream_xchacha20_xor` in place, so that applying it twice with the same key and nonce restores `buf`.
- R8 `kdf_derive(key: &Secret<32>, context: &KdfContext) -> Result<Secret<32>, CryptoError>` MUST call `crypto_kdf_derive_from_key` with `subkey_len = 32`, `subkey_id = 0` and the 8-byte context; `KdfContext` MUST be constructible only from exactly 8 bytes.
- R9 `hash(input: &[u8]) -> Result<[u8; 32], CryptoError>` MUST be `crypto_generichash` with `outlen = 32` and no key; `keyed_hash(key: &Secret<32>, input: &[u8]) -> Result<Secret<32>, CryptoError>` MUST be the same with the 32-byte key.
- R10 `sign_keypair_from_seed(seed: &Secret<32>) -> Result<(PublicKey, Secret<64>), CryptoError>` MUST call `crypto_sign_seed_keypair`; `sign_keypair() -> Result<(PublicKey, Secret<64>), CryptoError>` MUST call `crypto_sign_keypair`; `sign_detached(sk: &Secret<64>, message: &[u8]) -> Result<Signature, CryptoError>` MUST call `crypto_sign_detached`; `verify_detached(pk: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError>` MUST call `crypto_sign_verify_detached` and return `CryptoError::Forged` for a wrong signature, a wrong message, a non-canonical `S` (`S + L`), an identity or small-order `pk`, a small-order `R` and a non-canonical `pk`.
- R11 `password_key(password: &[u8], salt: &Salt) -> Result<Secret<32>, CryptoError>` MUST call `crypto_pwhash` with `alg = crypto_pwhash_ALG_ARGON2ID13`, `opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE` (2) and `memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE` (67 108 864 B); an allocation failure MUST surface as `CryptoError::OutOfMemory`.
- R12 `secretbox_seal(key: &Secret<32>, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>` MUST return the `crypto_secretbox_easy` output (16-byte MAC followed by ciphertext); `secretbox_open` MUST return the plaintext or `CryptoError::Forged`.
- R13 `pad(buf: &mut Vec<u8>, block: usize) -> Result<(), CryptoError>` MUST call `sodium_pad` so that the result length is the smallest multiple of `block` strictly greater than the input length; `unpad(buf: &[u8], block: usize) -> Result<usize, CryptoError>` MUST call `sodium_unpad` and return the unpadded length or `CryptoError::BadPadding`.
- R14 Every variable-length input (`aad`, `plaintext`, `ciphertext`, `buf`, `message`, `input`) MUST be rejected with `CryptoError::TooLong` above `MAX_INPUT = 65 535` bytes; `password` MUST be rejected with `CryptoError::TooLong` above 1 024 bytes and with `CryptoError::BadLength` when empty; `block` outside 1..=65 535 MUST be rejected with `CryptoError::BadLength`; all checks run before any libsodium call.
- R15 `CryptoError` MUST have exactly the unit variants `InitFailed`, `TooLong`, `BadLength`, `Forged`, `BadPadding`, `OutOfMemory`, in this order, and no variant MUST carry data; `Debug` of `PublicKey` MUST print only the lowercase hex of its first 4 bytes followed by `…`; `Signature`, `Nonce`, `Salt` and `KdfContext` MUST print their full lowercase hex.
- R16 `core` MUST depend only on `libsodium-sys-stable` (default features, bundled source, static link; the `use-pkg-config` feature MUST NOT be enabled) and `zeroize` (feature `zeroize_derive`), with `proptest` as the only dev dependency; `cargo deny --all-features check` MUST pass.
- R17 The workspace MUST have a `clippy.toml` whose `disallowed-methods` include `std::time::SystemTime::now`, `std::time::Instant::now`, `std::thread::sleep`, `std::fs::read`, `std::fs::write`, `std::fs::File::open`, `std::fs::File::create` and `std::net::TcpStream::connect`, with a reason citing AGENTS 10; `cargo clippy --all-targets --all-features -- -D warnings` MUST pass.
- R18 Every libsodium output buffer that holds a seed, a secret key or a derived key MUST be wrapped in a `Secret` before the wrapper returns, and every temporary copy MUST be wiped with `sodium_memzero` before the function returns; `Secret::zeroize()` MUST leave all `N` bytes at zero.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `aad`, `plaintext`, `ciphertext`, `buf`, `message`, `input` | 0..=65 535 B (`MAX_INPUT`) | `TooLong` |
| `password` | 1..=1 024 B | 0 → `BadLength`; > 1 024 → `TooLong` |
| `block` (padding) | 1..=65 535 | `BadLength` |
| `ciphertext` passed to `aead_decrypt` / `secretbox_open` | ≥ 16 B | `Forged` |
| Fixed sizes | `Nonce` 24, `Salt` 16, `KdfContext` 8, `PublicKey` 32, `Signature` 64, `Secret<32>`, `Secret<64>` | not constructible (types) |

## Interface

```
crates/core/src/crypto.rs              pub(crate) module root: types, re-exports, `init()`, `SECRET_TYPES`
crates/core/src/crypto/ffi.rs          the only `unsafe`: thin typed calls into libsodium-sys-stable
crates/core/src/crypto/secret.rs       Secret<N>
crates/core/src/crypto/tests.rs        s010_* tests and the vector loader for 010.json
clippy.toml                            disallowed-methods (R17)
```

```rust
pub(crate) const MAX_INPUT: usize = 65_535;

pub(crate) struct Secret<const N: usize>([u8; N]);            // R3
pub(crate) struct Nonce(pub(crate) [u8; 24]);
pub(crate) struct Salt(pub(crate) [u8; 16]);
pub(crate) struct KdfContext([u8; 8]);
pub(crate) struct PublicKey(pub(crate) [u8; 32]);
pub(crate) struct Signature(pub(crate) [u8; 64]);

pub(crate) enum CryptoError { InitFailed, TooLong, BadLength, Forged, BadPadding, OutOfMemory }

pub(crate) fn ct_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool;
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError>;
impl<const N: usize> Secret<N> {
    pub(crate) fn from_bytes(bytes: [u8; N]) -> Self;
    pub(crate) fn random() -> Result<Self, CryptoError>;
    pub(crate) fn expose(&self) -> &[u8; N];
}
impl KdfContext { pub(crate) const fn new(bytes: [u8; 8]) -> Self; }

pub(crate) fn aead_encrypt(key: &Secret<32>, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn aead_decrypt(key: &Secret<32>, nonce: &Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn stream_xor(key: &Secret<32>, nonce: &Nonce, buf: &mut [u8]) -> Result<(), CryptoError>;
pub(crate) fn kdf_derive(key: &Secret<32>, context: &KdfContext) -> Result<Secret<32>, CryptoError>;
pub(crate) fn hash(input: &[u8]) -> Result<[u8; 32], CryptoError>;
pub(crate) fn keyed_hash(key: &Secret<32>, input: &[u8]) -> Result<Secret<32>, CryptoError>;
pub(crate) fn sign_keypair_from_seed(seed: &Secret<32>) -> Result<(PublicKey, Secret<64>), CryptoError>;
pub(crate) fn sign_keypair() -> Result<(PublicKey, Secret<64>), CryptoError>;
pub(crate) fn sign_detached(sk: &Secret<64>, message: &[u8]) -> Result<Signature, CryptoError>;
pub(crate) fn verify_detached(pk: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError>;
pub(crate) fn password_key(password: &[u8], salt: &Salt) -> Result<Secret<32>, CryptoError>;
pub(crate) fn secretbox_seal(key: &Secret<32>, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn secretbox_open(key: &Secret<32>, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn pad(buf: &mut Vec<u8>, block: usize) -> Result<(), CryptoError>;
pub(crate) fn unpad(buf: &[u8], block: usize) -> Result<usize, CryptoError>;
```

Every function returns `Result` because each one may be the first libsodium call of the process (R2). `Nonce`, `Salt`, `PublicKey` and `Signature` are public data: `Clone`, `Copy`, `PartialEq` via `ct_eq`, and the `Debug` of R15. `KdfContext` is a protocol literal: `Clone`, `Copy`, `Debug`.

## Security

- Secrets: `Secret<32>` (root, master, header and message keys, seeds, password-derived keys) and `Secret<64>` (Ed25519 secret keys). Redacted `Debug`, no `Display`, zeroized on drop (R3, R18).
- Nothing in this module logs, formats a secret or puts bytes in an error (R15). There is no logging dependency in `core`.
- All inputs are length-checked before reaching libsodium (R14); libsodium performs the tag, signature and padding checks and the wrapper maps each failure to one variant.
- Signature verification is strict by construction: `libsodium-sys-stable` builds libsodium from source without `ED25519_COMPAT` (R10, §4). The negative vectors of "Vectors" prove it at test time, so a future build change cannot silently weaken it.
- Constant time: `ct_eq` for every fixed-size comparison (R4); tag and signature comparisons happen inside libsodium.

## Public API changes

- None at the core boundary: the whole module is `pub(crate)`. Spec 027 decides how `CryptoError` maps into the public `Error` of `docs/spec.md` §9.

## Test cases

Every test is in `crates/core/src/crypto/tests.rs` unless stated; every negative test asserts the exact variant.

- T01 (covers R1): `s010_t01_r01_unsafe_only_in_ffi` reads every `.rs` under `crates/core/src` with `include_str!`/a build-time list and asserts the token `unsafe` appears only in `crypto/ffi.rs`; clippy `undocumented_unsafe_blocks` covers the `// SAFETY:` comments.
- T02 (covers R2): `s010_t02_r02_init_runs_once`: two calls to `crypto::init()` return `Ok` and the `OnceLock` is set once (observable through a counter in a test-only hook).
- T03 (covers R3): `s010_t03_r03_debug_is_redacted`: `format!("{:?}")` of each entry of `SECRET_TYPES` (one `Secret<32>`, one `Secret<64>`, both non-zero) is exactly `[REDACTED]`. `s010_t04_r03_secret_has_no_forbidden_traits` is a compile-fail doctest (`compile_fail`) per forbidden trait (`Clone`, `Copy`, `Default`, `Display`).
- T05 (covers R4): `s010_t05_r04_ct_eq_agrees_with_equality`: proptest over pairs of `[u8; 32]`, `ct_eq(a, b) == (a == b)`.
- T06 (covers R5): `s010_t06_r05_random_bytes_differ`: two `random_bytes::<32>()` differ; `Secret::<32>::random()` is not all zeros.
- T07 (covers R6): `s010_t07_r06_aead_known_answer` on the AEAD vectors of `010.json`; `s010_t08_r06_aead_roundtrip` proptest over plaintext 0..=4 096 B and `aad` 0..=128 B; `s010_t09_r06_aead_mutation`: flipping one byte of ciphertext, tag, `aad` or nonce → `Forged`.
- T10 (covers R7): `s010_t10_r07_stream_xor_is_involution` proptest; `s010_t11_r07_stream_known_answer` on the stream vector.
- T12 (covers R8): `s010_t12_r08_kdf_known_answer` on the KDF vectors; two different contexts give different subkeys.
- T13 (covers R9): `s010_t13_r09_hash_known_answer` (unkeyed and keyed BLAKE2b vectors).
- T14 (covers R10): `s010_t14_r10_sign_known_answer` (RFC 8032 vectors: seed → `pk`, message → signature); `s010_t15_r10_verify_rejects_malformed` on the negative vectors `signature_s_plus_l`, `pk_identity`, `pk_small_order`, `r_small_order`, `pk_non_canonical`, `wrong_message`, `wrong_pk` → `Forged`; `s010_t16_r10_sign_roundtrip` proptest.
- T17 (covers R11): `s010_t17_r11_password_key_known_answer` on the Argon2id13 vector; a different salt gives a different key.
- T18 (covers R12): `s010_t18_r12_secretbox_known_answer`; `s010_t19_r12_secretbox_roundtrip_and_mutation` (flip → `Forged`).
- T20 (covers R13): `s010_t20_r13_pad_unpad_roundtrip` proptest over input 0..=4 096 B and block in {16, 1 024}; `s010_t21_r13_unpad_rejects_bad_padding`: a buffer of zeros and a buffer not a multiple of `block` → `BadPadding`.
- T22 (covers R14): `s010_t22_r14_inputs_over_max_are_too_long`: each variable-length input at `MAX_INPUT + 1` → `TooLong` for every function; empty password → `BadLength`; 1 025-byte password → `TooLong`; `block = 0` and `block = 65 536` → `BadLength`.
- T23 (covers R15): `s010_t23_r15_error_variants_are_unit_and_ordered`: `CryptoError` has 6 variants in the stated order (asserted via `Debug` strings); `s010_t24_r15_public_key_debug_is_prefix`: `Debug` of a `PublicKey` equals the 8 hex chars of its first 4 bytes + `…`; `Nonce`, `Salt`, `Signature`, `KdfContext` print full hex.
- T25 (covers R16): `s010_t25_r16_manifest_pins_dependencies` reads `crates/core/Cargo.toml` and asserts exactly `libsodium-sys-stable` and `zeroize` under `[dependencies]` and `proptest` under `[dev-dependencies]`, and that `use-pkg-config` is absent; `cargo deny --all-features check` green (CI `s001_t03_r03_cargo_deny`).
- T26 (covers R17): `s010_t26_r17_clippy_toml_disallows_clock_fs_net` reads `clippy.toml` and asserts each listed method; CI `s001_t02_r02_clippy_denies_warnings` green.
- T27 (covers R18): `s010_t27_r18_zeroize_clears_bytes`: after `zeroize()`, `expose()` is all zeros for `Secret<32>` and `Secret<64>`; `sodium_memzero` on temporaries is a review item of `ffi.rs` (each such call cites R18).

## Vectors

`specs/vectors/010.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Unlike later specs, these vectors are **transcribed from published sources**, not generated by the core, because the wrapper must match the standards, not itself; the source of each is in its `name`:

| name | kind | source |
| --- | --- | --- |
| `aead_xchacha20poly1305_ietf` | positive | libsodium `test/default/aead_xchacha20poly1305.c` (key, nonce, aad, message → ciphertext) |
| `stream_xchacha20` | positive | libsodium `test/default/xchacha20.c` |
| `kdf_subkey_0` | positive | libsodium `test/default/kdf.c` (context, subkey 0) |
| `blake2b_256_abc`, `blake2b_256_keyed` | positive | RFC 7693 test vectors, `outlen = 32` |
| `ed25519_rfc8032_test1`, `_test2`, `_test3` | positive | RFC 8032 §7.1 (seed, pk, message, signature) |
| `signature_s_plus_l`, `pk_identity`, `pk_small_order`, `r_small_order`, `pk_non_canonical` | negative | libsodium `test/default/sign.c` malformed cases, `expected.error = "Forged"` |
| `wrong_message`, `wrong_pk` | negative | derived from `ed25519_rfc8032_test1` |
| `argon2id13_interactive` | positive | libsodium `test/default/pwhash_argon2id.c` (password, salt → 32-byte key) |
| `secretbox_easy` | positive | libsodium `test/default/secretbox_easy.c` |
| `pad_1024` | positive | one input of 100 B → padded length 1 024 |

Mutation table (AEAD and secretbox): any single byte of `ciphertext`, `tag`/`mac`, `aad` or `nonce` → `Forged`; padding: any non-zero byte after the `0x80` marker → `BadPadding`. There is no Store in this spec, so `commits = 0` is trivially true and not asserted.

## Acceptance criterion

`cargo test -p privatechat-core s010_` green; `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny --all-features check` and `cargo build` from a clean checkout without a system libsodium green; human review of `ffi.rs` confirming every `unsafe` block has a `// SAFETY:` comment that states the buffer-length invariant.

## Out of scope

- Domain tags, KDF contexts, `channel_id`, `K_msg`, `K_hdr`, `mk`, the envelope, the payload and the fingerprint (specs 011–014).
- The public `Error` of `docs/spec.md` §9 and its mapping from `CryptoError` (spec 027).
- Fuzz targets: this module parses nothing; the fuzz harness (spec 016) targets `decrypt`, the payload and the config parsers.
- The `tracing`-based "no secrets in logs" test of `docs/spec.md` §8 "Logging": there is no log emitter yet (see Open questions).
- Any primitive not in the §4 table (no X25519, no `crypto_box`, no SHA-2).

## Open questions

- [ ] 010-R15: AGENTS 19 says "the log test of spec 010"; `core` has no logging dependency until the session (spec 021). Proposal: the `tracing` subscriber test lives in spec 021 and AGENTS 19 is updated when 021 is written.
- [ ] 010-R16: the libsodium version is the one bundled by the pinned `libsodium-sys-stable` (recorded in `Cargo.lock`). Proposal: bumping it is a `chore:` commit with `cargo deny` green, no ADR, as long as the 010 vectors still pass.
- [ ] 010-R14: `MAX_INPUT = 65 535` is a wrapper bound, not a protocol one; specs 013 and 011 enforce the exact §4/§5 limits (64 511 B plaintext, blob ≤ 64 673 B). Confirm that the wrapper should stay protocol-agnostic.

## History

- 2026-09-20 draft · 2026-09-20 in review
