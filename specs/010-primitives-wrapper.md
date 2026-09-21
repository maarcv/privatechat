# 010 — Primitives wrapper

Status: accepted
Phase: 1
Related ADRs: 0002, 0005, 0012
Depends on: 000, 001
Blocks: 011, 012, 013, 014, 015, 016
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-21

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
- R14 The wrapper MUST reject, before any libsodium call, exactly the inputs that libsodium would abort on or that would overflow the wrapper's own arithmetic, and nothing else: `plaintext` of `aead_encrypt` and `secretbox_seal` whose length plus 16 does not fit in `usize` → `CryptoError::TooLong`; `buf` of `pad` whose length plus `block` does not fit in `usize` → `CryptoError::TooLong`; `block = 0` → `CryptoError::BadLength`; `password` empty → `CryptoError::BadLength`, above 1 024 bytes → `CryptoError::TooLong`. `aad`, `ciphertext`, `message`, `input` and `buf` of `stream_xor` MUST NOT be bounded by this module. Every protocol or storage bound (payload, blob, frame, record, `state.bin`) lives in the spec of the caller.
- R15 `CryptoError` MUST have exactly the unit variants `InitFailed`, `TooLong`, `BadLength`, `Forged`, `BadPadding`, `OutOfMemory`, in this order, and no variant MUST carry data; `Debug` of `PublicKey` MUST print only the lowercase hex of its first 4 bytes followed by `…`; `Signature`, `Nonce`, `Salt` and `KdfContext` MUST print their full lowercase hex.
- R16 `core` MUST depend only on `libsodium-sys-stable` (default features, bundled source, static link; the `use-pkg-config` feature MUST NOT be enabled) and `zeroize` (feature `zeroize_derive`), with `proptest` as the only dev dependency; `cargo deny --all-features check -D checksum-mismatch` MUST pass. `deny.toml` MUST pin the SHA-256 of that crate's build script in `[[bans.build.bypass]]`, because the script falls back to fetching libsodium over plain HTTP when it cannot read the archive vendored in the crate, and a change to how libsodium is obtained MUST NOT arrive unread. `crypto::init()` MUST expose `sodium_version_string()` and a test MUST assert it equals `1.0.22`, the version this spec pins.
- R17 The workspace MUST have a `clippy.toml` whose `disallowed-methods` include `std::time::SystemTime::now`, `std::time::Instant::now`, `std::thread::sleep`, `std::fs::read`, `std::fs::write`, `std::fs::File::open`, `std::fs::File::create` and `std::net::TcpStream::connect`, with a reason citing AGENTS 10; `cargo clippy --all-targets --all-features -- -D warnings` MUST pass.
- R18 Every libsodium output buffer that holds a seed, a secret key or a derived key MUST be wrapped in a `Secret` before the wrapper returns, and every temporary copy MUST be wiped with `sodium_memzero` before the function returns; `Secret::zeroize()` MUST leave all `N` bytes at zero.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `plaintext` (`aead_encrypt`, `secretbox_seal`) | `len + 16 ≤ usize::MAX` | `TooLong` |
| `buf` (`pad`) | `len + block ≤ usize::MAX` | `TooLong` |
| `block` (padding) | ≥ 1 | `BadLength` |
| `password` | 1..=1 024 B (wrapper guard, not a libsodium bound: the protocol password is 7 BIP-39 words) | 0 → `BadLength`; > 1 024 → `TooLong` |
| `aad`, `ciphertext`, `message`, `input`, `buf` of `stream_xor` | unbounded here; bounded by the caller's spec | — |
| `ciphertext` passed to `aead_decrypt` / `secretbox_open` | ≥ 16 B | `Forged` |
| Fixed sizes | `Nonce` 24, `Salt` 16, `KdfContext` 8, `PublicKey` 32, `Signature` 64, `Secret<32>`, `Secret<64>` | not constructible (types) |

Protocol and storage bounds: 64 511 B payload and 64 673 B blob (specs 011-config-format, 013-wire-message), 70 000 B frame (`docs/spec.md` §6), records and `state.bin` (spec 020-store-files).

## Interface

```
crates/core/src/crypto.rs              pub(crate) module root: types, re-exports, `init()`, `SECRET_TYPES`
crates/core/src/crypto/ffi.rs          the only `unsafe`: thin typed calls into libsodium-sys-stable
crates/core/src/crypto/secret.rs       Secret<N>
crates/core/src/crypto/tests.rs        s010_* tests and the vector loader for 010.json
clippy.toml                            disallowed-methods (R17)
```

```rust
pub(crate) fn checked_output_len(len: usize, extra: usize) -> Result<usize, CryptoError>; // R14: len + extra, or TooLong

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
- The wrapper rejects only what libsodium would abort on or what would overflow (R14); it holds no protocol number. Every size policy lives in the spec of the caller, so a bound that changes there never has to be mirrored here. libsodium performs the tag, signature and padding checks and the wrapper maps each failure to one variant.
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
- T22 (covers R14): `s010_t22_r14_wrapper_bounds_are_the_primitives`: `aead_encrypt` and `secretbox_seal` of a 1 MiB plaintext succeed and round-trip (above every protocol bound, proving the wrapper imposes none); `checked_output_len(usize::MAX − 15, 16)` and `checked_output_len(usize::MAX, 1)` → `TooLong`; `checked_output_len(100, 16)` → `Ok(116)`; empty password → `BadLength`; 1 025-byte password → `TooLong`; `block = 0` → `BadLength`.
- T23 (covers R15): `s010_t23_r15_error_variants_are_unit_and_ordered`: `CryptoError` has 6 variants in the stated order (asserted via `Debug` strings); `s010_t24_r15_public_key_debug_is_prefix`: `Debug` of a `PublicKey` equals the 8 hex chars of its first 4 bytes + `…`; `Nonce`, `Salt`, `Signature`, `KdfContext` print full hex.
- T25 (covers R16): `s010_t25_r16_manifest_pins_dependencies` reads `crates/core/Cargo.toml` and asserts exactly `libsodium-sys-stable` and `zeroize` under `[dependencies]` and `proptest` under `[dev-dependencies]`, and that `use-pkg-config` is absent; `s010_t28_r16_deny_pins_the_build_script` reads `deny.toml` and asserts the `[[bans.build.bypass]]` entry for `libsodium-sys-stable`; `s010_t29_r16_libsodium_version_is_pinned` asserts `sodium_version_string()` is `1.0.22`; `cargo deny --all-features check -D checksum-mismatch` green (CI `s001_t03_r03_cargo_deny`).
- T26 (covers R17): `s010_t26_r17_clippy_toml_disallows_clock_fs_net` reads `clippy.toml` and asserts each listed method; CI `s001_t02_r02_clippy_denies_warnings` green.
- T27 (covers R18): `s010_t27_r18_zeroize_clears_bytes`: after `zeroize()`, `expose()` is all zeros for `Secret<32>` and `Secret<64>`; `sodium_memzero` on temporaries is a review item of `ffi.rs` (each such call cites R18).

## Vectors

`specs/vectors/010.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Unlike later specs, these vectors are not produced by the core: the wrapper must match the standards, not itself. Each one declares its provenance in `source` (`published`, `derived` or `pinned`) and names it in `origin`.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `aead_xchacha20poly1305_ietf` | positive | published | libsodium `test/default/aead_xchacha20poly1305.c` and `.exp` (key, nonce, aad, message of 114 bytes → ciphertext of 130) |
| `stream_xchacha20` | positive | published | libsodium `test/default/xchacha20.c`, `tv_stream_xchacha20` `tvs[0]`: the keystream, which `stream_xor` over a zero buffer reproduces |
| `blake2b_256_keyed` | positive | published | libsodium `test/default/generichash.exp`, iteration 31 of the `main` loop: input of 31 bytes, key of 32, `outlen = 32` |
| `ed25519_rfc8032_test1`, `_test2`, `_test3` | positive | published | RFC 8032 §7.1, byte-identical to `test_data[0..2]` of libsodium `test/default/sign.c` (seed → `pk`, message → signature) |
| `secretbox_easy` | positive | published | libsodium `test/default/secretbox_easy.c` and `.exp` (message of 131 bytes → output of 147) |
| `signature_s_plus_l` | negative | published | libsodium `test/default/sign.c`, `add_l()` applied to the `S` half of the `ed25519_rfc8032_test1` signature |
| `pk_identity` | negative | published | libsodium `test/default/sign.c`: 32 zero bytes as `pk` |
| `pk_small_order` | negative | published | libsodium `test/default/sign.c`: `pk = 3eee494f…ab36` |
| `pk_non_canonical` | negative | published | libsodium `test/default/sign.c`, `non_canonical_p` (`f6ff…ff7f`) |
| `r_small_order` | negative | published | libsodium `test/default/sign.c`: the `R` half set to `db ff … ff` |
| `wrong_message`, `wrong_pk` | negative | derived | `ed25519_rfc8032_test1` with the message of `_test2` and with the `pk` of `_test2` |
| `pad_1024` | positive | derived | ISO/IEC 7816-4, which `sodium_pad` implements: an input of 100 bytes becomes `input ‖ 0x80 ‖ 923 × 0x00` |
| `unpad_all_zero` | negative | derived | a buffer of 1 024 zero bytes has no `0x80` marker → `BadPadding` |
| `blake2b_256_unkeyed` | positive | **pinned** | no published source; agrees with the BLAKE2 reference implementation |
| `kdf_subkey_0` | positive | **pinned** | no published source |
| `argon2id13_interactive` | positive | **pinned** | no published source |

**Why three vectors are `pinned`.** Published vectors exist for these three primitives, but never at the parameters `docs/spec.md` §4 fixes, and the parameters are not ours to change:

- `blake2b_256_unkeyed`: RFC 7693 publishes BLAKE2b with `outlen = 64`. A digest of 32 bytes is not the truncation of one of 64 — the length enters the parameter block — and the variable-length loop of libsodium's `generichash.c` is always keyed, so no unkeyed digest of 32 bytes is published anywhere. R9 fixes `outlen = 32`. This value is byte-identical to the one Python's `hashlib` produces, which comes from the BLAKE2 reference implementation and not from libsodium, so two independent implementations agree on it; `origin` records that.
- `kdf_subkey_0`: libsodium's `kdf.exp` prints 64-byte subkeys for `subkey_id` 0..9, and a 32-byte subkey only for `subkey_id = 32`, because its second loop ties the output length to the id. R8 fixes `subkey_len = 32` with `subkey_id = 0`, a combination that is published nowhere.
- `argon2id13_interactive`: libsodium's `pwhash_argon2id.c` uses ad-hoc `opslimit`/`memlimit` values and outputs of 155..250 bytes, never the `INTERACTIVE` pair with an output of 32 bytes. RFC 9106 publishes one Argon2id vector, with `p = 4`; `crypto_pwhash` forces `p = 1`, so it cannot be reproduced through the wrapper. R11 fixes `INTERACTIVE` and 32 bytes.

A `pinned` vector proves no conformance. What it does is fail the moment the bundled libsodium version, a build flag or the wrapper changes the bytes, which is the failure that would otherwise reach a user as an unreadable history or as two platforms that cannot decrypt each other. For the two BLAKE2b cases a `published` neighbour (`blake2b_256_keyed`) exercises the same code path at the same output length, so the pinned value is not the only evidence that the call is right; for Argon2id there is no such neighbour, and `s010_t17` additionally asserts that a different salt yields a different key.

Mutation table (AEAD and secretbox): any single byte of `ciphertext`, `tag`/`mac`, `aad` or `nonce` → `Forged`; padding: any non-zero byte after the `0x80` marker → `BadPadding`. These are asserted as tests over the positive vectors (T09, T19, T21), not enumerated as JSON entries. There is no Store in this spec, so `commits = 0` is trivially true and not asserted.

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
- [ ] 010-R16: bumping `libsodium-sys-stable` moves three pinned values at once — the version in `s010_t29`, the build-script SHA-256 in `deny.toml` and, if the library ever changes an output, the three `pinned` vectors. Proposal: a `chore:` commit, no ADR, on the condition that the `published` vectors still pass untouched and that a human has read the new build script; a `pinned` vector that moves is a red flag, not a value to update on sight.
- [x] 010-R14 — closed on 2026-09-21: `MAX_INPUT = 65 535` was a protocol number in a layer that knows no protocol, and ADR 0021 (`state.bin` sealed in one `secretbox` call, ≤ 550 peers plus `outbox`) already exceeds it. R14 now bounds only what libsodium would abort on or what would overflow; the protocol and storage bounds live in specs 011-config-format, 013-wire-message and 020-store-files and in `docs/spec.md` §6. Pending elsewhere, not here: spec 020-store-files has to fix the maximum size of a peer `label` and of the `outbox`, otherwise `state.bin` has no upper bound at all.

## History

- 2026-09-20 draft · 2026-09-20 in review · 2026-09-21 accepted (Marc Vilardebó) · 2026-09-21 "Vectors" amended: three primitives have no published vector at the parameters §4 fixes, so they are `pinned` and each vector declares its `source` (Marc Vilardebó) · 2026-09-21 R14 amended: the wrapper bounds only what libsodium requires; the protocol number 65 535 leaves this spec (Marc Vilardebó)
