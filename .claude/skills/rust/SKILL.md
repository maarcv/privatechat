---
name: rust
description: Rust coding standard for this repository's `core`, `store` and `server` crates — the official Rust Style Guide as the baseline, crate layout, types, writing code under the workspace lints, the inside of `ffi.rs`, server concurrency, documentation, testing and tooling. Use it whenever you create or edit any `.rs` file, a `Cargo.toml`, a fuzz target, a test vector loader or a clippy/rustfmt config, and when reviewing Rust code. It assumes you have read the `architecture` skill first. `references/patterns.md` has the reference shapes, written to pass the workspace lints; read only the section you need — §1 `Secret<N>`, §2 fixed-offset parser, §3 `Store`/`WriteBatch`, §4 sans-I/O `Session`, §5 encrypt ordering, §6 vector loader.
---

# Rust standard

`core` is the only place where cryptography and the protocol exist. `store`
persists its state. `server` relays blobs. All three are compiled with the
workspace lints at `deny` (AGENTS 4), so most of this skill is about writing
code that is *clear*, not code that merely compiles. The rules themselves are
`AGENTS.md`; this skill cites them by number and never restates them.

## The Rust Style Guide is the baseline

The official [Rust Style Guide](https://doc.rust-lang.org/style-guide/) is
normative. Its formatting chapters are what `rustfmt` produces with the
project's `rustfmt.toml`, so `cargo fmt --all` *is* the guide; never
hand-format against it or `#[rustfmt::skip]` without a reason comment. Its
non-formatting chapters (items, comments, `Cargo.toml`) are review items. When
the guide and a rule below disagree, the rule below is a project-specific
tightening, never a relaxation.

## Crate and module layout

- `lib.rs` is thin: module declarations, the public re-exports, crate docs.
  No logic.
- Modules are named after the domain concept they own (`crypto`, `proto`,
  `session`, `peers`), one concept each. Use `foo.rs` + `foo/` directories,
  never `mod.rs`.
- Default visibility is private. Reach for `pub(crate)` before `pub`. The
  public API of `core` is the list in `docs/spec.md` §9; anything else that is
  `pub` needs a reason.
- One `Error` enum per crate at the crate root (`core::Error`), written by
  hand (`core` carries no dependency beyond libsodium and `zeroize`, spec 010
  R16). Variants mirror the spec's conditions one-to-one. No `anyhow`, no
  `Box<dyn Error>` in library crates; `server`'s `main` may use `anyhow` for
  startup only.
- Every number that appears in the spec is a named `const` next to the code
  that uses it, with a doc comment pointing at the section — offsets and
  ranges too (`CHANNEL_ID_RANGE: Range<usize> = 1..17`). Derive what can be
  derived (`MIN_BLOB = BLOB_OVERHEAD + PAD_BLOCK`) and pin the spec's literals
  in one test (`references/patterns.md` §2).

## Types

- **Newtypes for anything that is "some bytes with a meaning"**: `ChannelId([u8;
  16])`, `ServerId([u8; 16])`, `Counter(u64)`. Derive only what the type
  needs; a key type is `Secret<N>` (AGENTS 5, `references/patterns.md` §1)
  and derives nothing that could print or copy it.
- **Enums over booleans.** `PeerState::{Unknown, Labelled, Verified, Muted,
  Retired}` instead of three flags that admit eight states.
- **Construct-valid types.** `Payload::validate()` runs inside the constructor
  path used by both `encrypt` and `decrypt`, so an invalid `Payload` cannot
  exist.
- No lifetimes on `pub` types in `core` (the FFI surface); `pub(crate)`
  borrowing views like `Envelope<'a>` are preferred for parsers.
- No `Rc<RefCell<_>>` or `Arc<Mutex<_>>` in `core`: state belongs in the
  `Store` and changes in one commit (AGENTS 23).

## Writing under the lints

The lint list lives in `[workspace.lints]` of the root `Cargo.toml` (AGENTS 4).
In short: no `unwrap`/`expect`/`panic`, no indexing or slicing, no bare
arithmetic on external integers, no lossy casts. Write code that does not need
them:

```rust
// Slicing: use `get` and map the failure to the spec's variant.
let header = blob.get(..HEADER_LEN).ok_or(Error::BadLength)?;

// Arithmetic on external integers: checked or saturating, never bare — also
// where a previous check makes it "safe"; clippy cannot see the check, and
// `is_multiple_of` replaces `% == 0`.
let padded = len.checked_sub(BLOB_OVERHEAD).ok_or(Error::BadLength)?;
let aligned = padded.is_multiple_of(PAD_BLOCK);
let expires = received_at.checked_add(ttl_ms).ok_or(Error::Expired)?;
let gap = counter.saturating_sub(max_counter.saturating_add(1));

// Conversions: `try_from`, never `as`.
let len = u32::try_from(record.len()).map_err(|_| StoreError::TooLarge)?;
```

A `get` or `try_into` that cannot fail after validation still maps to the
nearest spec variant (`BadLength`), never to `unwrap`: that is the convention
for impossible-after-validation failures.

Tests relax exactly the four lints AGENTS 4 names:
`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used,
clippy::indexing_slicing, clippy::arithmetic_side_effects))]`. Even there
prefer `?` with `-> Result<(), Error>` test signatures and
`assert!(matches!(result, Err(Error::X)))` over `unwrap_err()`. `assert_eq!`
on byte slices is fine in tests; AGENTS 22 (`ct_eq`) is about production code.

The order of checks in `docs/spec.md` §4 "Verification on receive" is
normative: implement them in that order, each returning its own variant, so
that the spec's mutation table is a test you can write.

## Inside `ffi.rs`

AGENTS 12 fixes where `unsafe` may appear. Inside that one file:

- The `// SAFETY:` comment states the invariant that makes the block sound
  (buffer lengths, non-null, initialised).
- Wrap every libsodium call in a safe function with typed arguments
  (`fn aead_encrypt(key: &Secret<32>, nonce: &[u8; 24], ...)`) so the rest of
  `core` never sees a raw pointer or a length parameter.
- Call `sodium_init()` once via `std::sync::OnceLock` and return an error, not a
  panic, if it fails (spec 010 R2).
- `crypto::ct_eq` wraps `sodium_memcmp`; it is the only equality on fixed-size
  bytes in `core` (AGENTS 22).

## Concurrency

`core` and `store` are single-threaded by design: no `tokio`, no threads, no
`Send` bounds to think about. `server` uses `tokio`:

- Bounded channels only (`mpsc::channel(N)`), never `unbounded_channel`. When a
  channel is full, the spec says what happens (`rate_limited`); an unbounded
  queue says "OOM later".
- One writer thread owns the SQLite write connection, reads use a small pool
  of read-only connections, and every write is a `WriteRequest` to that
  thread (spec 032-storage-ttl R4, R9).
- Every task has an explicit shutdown path (`CancellationToken` or a
  `select!` on a shutdown signal). Tasks that "just run forever" leak on
  reload.
- A deadline on every await that touches the network. In the server they are
  measured with `Clock::mono_ms` and enforced by the deadline task, so that a
  manual clock drives them in tests (spec 032-storage-ttl R14, spec
  033-rate-limit-quotas R4, R5); `tokio::time::timeout` only where no
  `Clock` deadline applies.

## Documentation

- `//!` at the top of every module: what it owns, which spec section it
  implements, what it deliberately does not do.
- `///` on every `pub` item, with `# Errors` listing the variants and when,
  and `# Examples` as a doctest where the item is a parser or an encoder.
  `missing_docs` is a workspace warning that CI turns into an error.
- Inline comments explain *why* — cite the spec (`// §4 step 4: signature
  before any state so a forged header never drives an eviction.`) or the
  threat. Never narrate the code.

## Testing

- Names: AGENTS 6. One requirement may have several tests; every requirement
  has at least one.
- Test vectors are loaded from `specs/vectors/NNN.json`, which the reference
  script of spec 015 writes, never retyped in Rust (`references/patterns.md`
  §6). Hex literals are lowercase everywhere.
- **Table-driven** for anything with more than two cases:

  ```rust
  #[test]
  fn s013_t01_r01_rejects_bad_length() {
      for len in [1184usize, 64_674, 1_200] {
          let blob = vec![0u8; len];
          assert!(matches!(channel.decrypt(&blob, 0, 0), Err(Error::BadLength)), "len={len}");
          assert_eq!(store.commits(), 0); // commits other than the cursor (AGENTS 23)
      }
  }
  ```

- Test modules live at `foo/tests.rs`, declared from `foo.rs` with
  `#[cfg(test)] mod tests;`.
- The test `Store` counts commits other than the cursor's; every rejection
  asserts `commits == 0` and every stateful spec has a `FailingStore` test
  (AGENTS 23, `references/patterns.md` §3).
- Round-trip `proptest`s and fuzz targets: AGENTS 21. The spec's mutation
  table is a test of the full `decrypt` (flip a byte in each region, expect
  that region's variant); a parser-level test only asserts the flipped byte
  landed in the expected field. Say which level a test is at in its name.
- No `sleep`, no clock, no network in tests. Time is a parameter.
- Prefer many small tests with precise names over one test with twenty asserts:
  the name of the failing test is the bug report.

## Tooling

- The local CI commands are the list in `.github/CONTRIBUTING.md` (AGENTS 17),
  including the exact `cargo deny` invocation. Do not `#[allow]` a lint or
  `#[rustfmt::skip]` a block without a comment saying why; never allow the
  lints the workspace denies.
- Minimal features on every dependency (`default-features = false`) unless
  you need them (AGENTS 8).
- `edition = "2024"`, toolchain pinned in `rust-toolchain.toml`. No nightly
  features. The one nightly toolchain in the repository is the dated one the
  fuzz workflow uses for `cargo fuzz` (spec 016-fuzz-harness, R9).

## Project idioms

- `?` everywhere; `map_err` to the spec variant at the point where the
  meaning is known, not at the top.
- `Envelope::parse(blob, &channel_id)` for fixed-offset parsing, the first
  half of `verify` (`references/patterns.md` §2).
- `#[must_use]` on functions that return a value the caller must not drop
  (`encrypt` returns the reserved counter's blob — dropping it loses a counter).
- No `impl Trait` in return position on public `core` API (uniffi cannot see
  it). No feature flags in `core`: one build, one behaviour. No macros for
  anything a function can do.
