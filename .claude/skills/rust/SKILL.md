---
name: rust
description: Rust coding standard for this repository's `core`, `store` and `server` crates — the official Rust Style Guide (formatting via rustfmt, plus its naming, comment, item-ordering and Cargo.toml conventions), crate layout, types, error handling, ownership, `unsafe` policy, testing and tooling. Use it whenever you create or edit any `.rs` file, a `Cargo.toml`, a fuzz target, a test vector loader or a clippy/rustfmt config, and when reviewing Rust code. It assumes you have read the `architecture` skill first. `references/patterns.md` has compile-checked shapes; read only the section you need — §1 `Secret<N>`, §2 fixed-offset parser, §3 `Store`/`WriteBatch`, §4 sans-I/O `Session`, §5 encrypt ordering, §6 vector loader.
---

# Rust standard

`core` is the only place where cryptography and the protocol exist. `store`
persists its state. `server` relays blobs. All three are compiled with the
workspace lints at `deny`, so most of this skill is about writing code that is
*clear*, not code that merely compiles. Read `architecture` first; this skill
assumes its layering, error and naming rules.

## The Rust Style Guide is the baseline

The official [Rust Style Guide](https://doc.rust-lang.org/style-guide/) is
normative for this repository. Its formatting chapters (indentation, line
width, trailing commas, blocks, match arms, chains, `use` sorting, …) are
exactly what `rustfmt` produces with the project's `rustfmt.toml`, so
`cargo fmt --all` before every commit *is* the guide; never hand-format
against it or `#[rustfmt::skip]` without a reason comment. The guide's
non-formatting rules are not mechanical, so they are review items:

- **Casing (RFC 430):** `UpperCamelCase` for types, traits and enum variants;
  `snake_case` for functions, methods, fields, locals, modules and macros;
  `SCREAMING_SNAKE_CASE` for `const` and `static`. Generic parameters are
  single letters (`T`, `E`, `const N: usize`).
- **Reserved words:** use a raw identifier (`r#type`) or a trailing underscore
  (`type_`); never misspell (`typ`, `krate`).
- **Item order in a file:** `extern crate` (rare), then `use` imports, then
  `mod` declarations, then everything else. Group imports in three blocks
  separated by one blank line — `std`/`core`, external crates, this crate
  (`crate::`, `super::`, `self::`) — and let `rustfmt` version-sort inside
  each block. Avoid `#[path]` on modules; the file tree is the module tree.
- **Comments are sentences:** start with a capital letter, end with a period,
  one space after `//`. Prefer a comment on its own line; keep pure-comment
  lines ≤ 80 columns. Line comments over block comments. Doc comments (`///`)
  go **before** attributes; `//!` only at crate or module level.
- **Attributes:** one per line; a single `#[derive(…)]` per item, never two.
- **Expression-oriented code:** `let x = if c { a } else { b };`, never declare
  then assign in branches. Prefer `Foo::Bar` qualified enum literals except
  for the prelude (`Some`, `Ok`, `Err`). Prefer a unit struct `struct Marker;`
  to an empty `struct Marker {}`.
- **Operators:** parentheses whenever precedence is not obvious to a reader
  (`(a * b) + c`); compare by dereferencing (`*t == u`) rather than referencing
  (`t == &u`).
- **Hex literals** in lowercase everywhere (the spec's test vectors are
  lowercase hex too).
- **`Cargo.toml`:** `[package]` first; inside it `name`, then `version`, then
  the remaining keys version-sorted, and `description` **last**. Every other
  section has its keys version-sorted; one blank line between sections and
  none inside them; bare keys, `key = value` with single spaces; arrays that
  do not fit on one line are block-indented with a trailing comma.

When the guide and a rule below disagree, the rule below is a project-specific
tightening (e.g. no `unwrap`), never a relaxation.

## Crate and module layout

- `lib.rs` is thin: module declarations, the public re-exports, crate docs.
  No logic.
- Modules are named after the domain concept they own (`crypto`, `proto`,
  `session`, `peers`), one concept each. Use `foo.rs` + `foo/` directories,
  never `mod.rs` — the file name should tell you what is inside.
- Default visibility is private. Reach for `pub(crate)` before `pub`. The
  public API of `core` is the list in `docs/spec.md` §9; anything else that is
  `pub` needs a reason.
- One `Error` enum per crate at the crate root (`core::Error`), derived with
  `thiserror`. Variants mirror the spec's conditions one-to-one. No `anyhow`,
  no `Box<dyn Error>` in library crates; `server`'s `main` may use `anyhow`
  for startup only.
- Every number that appears in the spec is a named `const` next to the code
  that uses it, with a doc comment pointing at the section. That includes
  byte offsets and ranges (`CHANNEL_ID_RANGE: Range<usize> = 1..17`), not
  only lengths; derive what can be derived (`MIN_BLOB = BLOB_OVERHEAD +
  PAD_BLOCK`) and pin the spec's literals in one test:

  ```rust
  /// Fixed header length of the wire envelope: version(1) + channel_id(16) +
  /// enc_hdr(40) + nonce(24). `docs/spec.md` §4.
  pub(crate) const HEADER_LEN: usize = 81;
  ```

## Types

- **Newtypes for anything that is "some bytes with a meaning"**: `ChannelId([u8;
  16])`, `ServerId([u8; 16])`, `Counter(u64)`. A `[u8; 16]` can be passed where
  a `[u8; 32]` was meant; a `ChannelId` cannot. Derive only what the type
  needs; a key type must not derive `Clone`, `Default`, `Debug` or
  `PartialEq` (see `Secret<N>` in `references/patterns.md`).
- **Enums over booleans.** `PeerState::{Unknown, Labeled, Verified, Muted,
  Retired}` instead of `verified: bool, muted: bool, retired: bool`, which
  admits eight states of which five are meaningless.
- **Construct-valid types.** `Payload::validate()` runs inside the constructor
  path used by both `encrypt` and `decrypt`, so an invalid `Payload` cannot
  exist. Avoid "make it, then call `.check()`".
- **`Option` for absence, `Result` for failure.** Never `Option<Result<_>>`;
  never a sentinel value.
- Avoid `Rc<RefCell<_>>`, `Arc<Mutex<_>>` and lifetimes in public signatures
  inside `core`. If you need shared mutable state in `core`, the design has a
  problem — state belongs in the `Store` and changes in one commit.

## Errors and panics

The single source of the lint list is `[workspace.lints]` in the root
`Cargo.toml` (AGENTS 4 and `docs/spec.md` §10 point there; do not copy the
list anywhere else). In short: no `unwrap`/`expect`/`panic`, no indexing or
slicing, no bare arithmetic on external integers, no lossy casts. Write code
that does not need them:

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

Each crate root relaxes exactly four lints for tests, to build fixtures:
`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used,
clippy::indexing_slicing, clippy::arithmetic_side_effects))]`. Even there
prefer `?` with `-> Result<(), Error>` test signatures and
`assert!(matches!(result, Err(Error::X)))` over `unwrap_err()`. `assert_eq!`
on byte slices is fine in tests; AGENTS 22 (`ct_eq`) is about production
code.

Order of checks matters and is normative: `docs/spec.md` §4 "Verification on
receive" lists them; implement them in that order, each returning its own
variant, so that the mutation table in the spec is a test you can write.

## Ownership and signatures

- Take `&[u8]` for input, return `Vec<u8>` for output. Take `&str`, return
  `String`. Do not take `Vec<u8>` by value unless you will store it.
- `&mut self` on anything that changes state; `&self` otherwise. If a method
  needs `&mut self` only to update a cache, remove the cache.
- No lifetimes on `pub` types in `core` (the FFI surface). `pub(crate)`
  borrowing views like `Envelope<'a>` are fine and preferred for parsers.
- Iterators over indices: `for (i, item) in xs.iter().enumerate()`, never
  `for i in 0..xs.len() { xs[i] }`.

## `unsafe` and libsodium

`#![forbid(unsafe_code)]` everywhere except `crates/core/src/crypto/ffi.rs`, the one
file that calls `libsodium-sys-stable`. There:

- `#![deny(unsafe_op_in_unsafe_fn)]`; every `unsafe {}` block has a
  `// SAFETY:` comment stating the invariant that makes it sound (buffer
  lengths, non-null, initialised).
- Wrap every libsodium call in a safe function with typed arguments
  (`fn aead_encrypt(key: &Secret<32>, nonce: &[u8; 24], ...)`) so the rest of
  `core` never sees a raw pointer or a length parameter.
- Call `sodium_init()` once via `std::sync::OnceLock` and return an error, not a
  panic, if it fails.
- Compare fixed-size bytes with `sodium_memcmp` through `crypto::ct_eq`. Never
  `==` on `[u8; N]` anywhere in `core` (AGENTS 22). Not deciding where
  constant time matters is the whole point.

## Concurrency

`core` and `store` are single-threaded by design: no `tokio`, no threads, no
`Send` bounds to think about. `server` uses `tokio`:

- Bounded channels only (`mpsc::channel(N)`), never `unbounded_channel`. When a
  channel is full, the spec says what happens (`rate_limited`); an unbounded
  queue says "OOM later".
- One writer task owns the SQLite connection. Everything else sends it
  `WriteBatch`es.
- Every task has an explicit shutdown path (`CancellationToken` or a
  `select!` on a shutdown signal). Tasks that "just run forever" leak on
  reload.
- Timeouts on every await that touches the network (`tokio::time::timeout`).

## Documentation

- `//!` at the top of every module: what it owns, which spec section it
  implements, what it deliberately does not do.
- `///` on every `pub` item, with `# Errors` listing the variants and when,
  and `# Examples` as a doctest where the item is a parser or an encoder.
  `missing_docs` is a warning in the workspace and a blocker in review.
- Inline comments explain *why* — cite the spec (`// §4 step 5: signature
  before decrypt so a garbage header never reaches the AEAD.`) or the threat.
  Never narrate the code. They are complete sentences, in English, ending
  with a period (style guide).

## Testing

- Names: `sNNN_tTT_rRR_<what>` (`s013_t03_r02_rejects_bad_signature`). One
  requirement may have several tests; every requirement has at least one.
- Test vectors are loaded from `specs/vectors/NNN.json`, never retyped in
  Rust. A helper `vectors::load("013")` returns typed cases; the loader
  itself has one test.
- **Table-driven** for anything with more than two cases:

  ```rust
  #[test]
  fn s013_t01_r01_rejects_bad_length() {
      for len in [1184usize, 64_674, 1_200] {
          let blob = vec![0u8; len];
          assert!(matches!(channel.decrypt(&blob, 0, 0), Err(Error::BadLength)), "len={len}");
          assert_eq!(store.commits(), 0);
      }
  }
  ```

- Test modules live at `foo/tests.rs`, declared from `foo.rs` with
  `#[cfg(test)] mod tests;`. Tests can only be named when the spec exists:
  if there is no `specs/NNN-*.md` with numbered requirements, stop and write
  the spec first (AGENTS 1) — never invent `R` numbers.

- **Every rejection asserts `commits == 0`**; the test `Store` counts commits.
- **`proptest` round-trips** for every encoder/decoder pair
  (`encrypt(decrypt(x)) == x` for all `k`, all payload sizes) and **mutation
  tests** for every format. The spec's mutation table is a test of the full
  `decrypt` (flip a byte in each region, expect that region's variant); a
  parser-level test only asserts the flipped byte landed in the expected
  field. Say which level a test is at in its name.
- **`FailingStore`** that fails at commit *n*: reopen, assert the state equals
  the state before *n*.
- **Fuzz targets** in `crates/core/fuzz` for every `parse`, `decrypt`, `open_*`
  (AGENTS 21). Keep targets tiny: bytes in, call, ignore result, no panics.
- No `sleep`, no clock, no network in tests. Time is a parameter.
- Prefer many small tests with precise names over one test with twenty asserts:
  the name of the failing test is the bug report.

## Tooling

- `cargo fmt --all` (workspace `rustfmt.toml`, style edition 2024 = the Rust
  Style Guide) and `cargo clippy --all-targets -- -D warnings` clean before
  every commit (AGENTS 17). Do not `#[allow]` a lint or `#[rustfmt::skip]` a
  block without a comment saying why; never allow the lints the workspace
  denies.
- `cargo deny check` gates dependencies. Adding a crate needs one sentence in
  the PR. Minimal features (`default-features = false`) unless you need them.
- `edition = "2024"`, toolchain pinned in `rust-toolchain.toml`. Do not use
  nightly features.
- Generated code (uniffi) is not committed.

## Idioms to reach for

- `?` everywhere; `map_err` to the spec variant at the point where the
  meaning is known, not at the top.
- `Envelope::parse(blob, &channel_id)` for fixed-offset parsing (the parser
  needs the expected channel for check 1c, so it is not a `TryFrom`); see
  `references/patterns.md` §2.
- `#[must_use]` on functions that return a value the caller must not drop
  (`encrypt` returns the reserved counter's blob — dropping it loses a counter).
- `matches!` over `if let … { true } else { false }`.
- `let … else` for early returns on `Option`/`Result`.
- Small `struct`s with named fields over tuples with more than two elements.

## Idioms to avoid

- `clone()` to satisfy the borrow checker without understanding why; fix the
  ownership.
- `String` for anything that is not human text; `Vec<u8>` for bytes.
- `impl Trait` in return position on public `core` API (uniffi cannot see it).
- Macros for anything a function can do.
- Feature flags in `core`. One build, one behaviour.
