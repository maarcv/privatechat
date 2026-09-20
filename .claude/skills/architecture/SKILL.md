---
name: architecture
description: Project-wide architecture and code-quality standard for the private E2E chat (privatechat). Read this before writing, reviewing or refactoring ANY code in this repository, in any language, and before writing a feature spec — even for a "small" change, a test, a script or a one-line fix. It defines the layers and dependency direction (UI → Session → Channel → Store → crypto, dependencies pointing down), the size and naming rules, how errors and state are handled, what "simple" means here, the SDD workflow (spec → review → red tests → code) and the review checklist. The language skills (rust, kotlin, swift, typescript-svelte) assume you have read this one.
---

# Architecture and code standard

This project is a group chat where the server is a blind mailbox and the client
is where security actually happens. The owner's mandate is
**uncompromising and simple**; everything below exists to serve it.

`AGENTS.md` is the rulebook. The design it enforces comes, in order of
precedence, from the accepted feature spec `specs/NNN-*.md`, then
`docs/spec.md`, then the ADRs. This skill explains *how* to write code that
satisfies them. If two sources disagree, stop and open a question in the
feature spec rather than deciding.

## 1. Layers and the direction of dependencies

```
UI (Kotlin / Swift / Svelte)       pixels, sockets, keystore prompts. No logic.
   │  bytes, opaque handles, events
Session (core, sans-I/O)           protocol state machine: hello/subscribe/push/ack
   │
Channel (core)                     encrypt/decrypt, peers, counters, outbox
   │
Store (store crate)                two encrypted files per channel, atomic commit
   │
crypto (core::crypto)              the only module that touches libsodium
```

These are call layers. The crate graph is `store → core` and `server → core`;
`core` defines the `Store` trait and receives a `Box<dyn Store>`.

Dependencies point **down** only. `core` knows nothing about files, sockets,
clocks or screens: it receives bytes and a `now`, and returns bytes and events.
The UI knows nothing about the protocol: it opens a TLS socket, shovels frames
in both directions, and renders what `Session` tells it. This keeps the
security-critical code testable without a device and identical on three
platforms.

The core-boundary contract (AGENTS 20; the language skills add only their
mechanics):

- Boundaries carry **bytes and plain data**, never rich objects. A blob is
  `&[u8]`; `now` is `u64` milliseconds passed in — nothing in `core` reads a
  clock.
- `Config`, `Channel`, `Session` and `Settings` are opaque handles (uniffi
  `Object`); only `Received`, `Peer`, `Fingerprint`, `Gap` and `Event` are
  `Record`s. Secrets never cross the boundary by value.
- Passwords cross the boundary as bytes (`ByteArray`, `[UInt8]`,
  `Uint8Array`) and are zeroized on the UI side after the call.
- Outside the core no wiping is promised: what is promised is not retaining
  (no cache, no log, no `toString`).
- If a piece of logic could run on all three platforms, it belongs in `core`.
  If it can only run on one, it belongs in that client, and it should be thin.

## 2. What "simple" means here

Simple is not "short". Simple is **one obvious way to do each thing, with
nothing left over**. Concretely:

- **Delete before you add.** When you find yourself adding a flag, an option,
  a second code path or a "just in case" field, first ask what you could
  remove instead. A new feature has to close a specific hole.
- **No premature abstraction.** Write the concrete thing. Extract a trait,
  generic or helper only when the *third* caller appears and all three are
  genuinely the same. Two similar functions are cheaper than one wrong
  abstraction.
- **No clever code.** If a line needs a comment to explain *how* it works,
  rewrite the line. Comments explain *why* (a spec reference, a threat, a
  non-obvious constraint), never *what*.
- **One concept per module, one job per function.** A function that does two
  things has two failure modes and needs four tests. Split it.
- **Make illegal states unrepresentable.** Prefer an enum with three variants
  over two booleans; prefer a newtype `ChannelId([u8; 16])` over `[u8; 16]`;
  prefer a type that can only be constructed valid over a validate-later
  pattern.
- **Sizes are a smell detector, not a law:** functions ≤ ~40 lines, files ≤
  ~400 lines, ≤ 4 parameters. Exceeding them is fine when splitting would be
  worse — but notice it, and say why in the PR.

## 3. Errors and state

**Errors are values.** Every operation that can fail on external input returns a
result type (`Result<T, Error>` in Rust, `Result`/sealed types in Kotlin,
`throws` in Swift, discriminated unions in TypeScript). There is exactly one
error type per crate/module, with one variant per condition, in the spec's
order (rust `patterns.md` §2 for the envelope). Never fold two conditions into
one variant "for simplicity" — the negative test vectors need to tell them
apart.

Never panic on external data. In `core`, `store` and `server` the workspace
lints (single source: `[workspace.lints]` in the root `Cargo.toml`) make
`unwrap`, `expect`, `panic!`, indexing and unchecked arithmetic compile errors.
A panic in the decrypt path is a remote crash.

**State lives in one place and changes in one commit.** Every logical operation
(receive a message, send a message, retire a key) becomes exactly one
`Store::commit(WriteBatch)`. A rejected message writes nothing except the
cursor. `encrypt` reserves the counter *before* it returns a blob. If you are
writing to state in two places, you have invented a race.

**Time is a parameter.** Nothing in `core` or `store` reads a clock. This makes
TTL tests deterministic and lets the fuzzer drive time.

## 4. Naming

- Names say what a thing *is* or *does*, in full words: `channel_id`, not
  `chid`; `decrypt_blob`, not `proc`. The only accepted abbreviations are the
  ones the spec itself uses as protocol literals (`pk`, `sk`, `mk`, `ttl`).
- Functions are verbs (`encrypt`, `retire_peer`), types are nouns
  (`WireMessage`), booleans read as predicates (`is_retired`, `has_more`).
- Test names encode traceability: `sNNN_tTT_rRR_<what_it_checks>` — spec 013,
  test 03, requirement 02. `scripts/check_requirements.sh` relies on it.
- Error variants name the condition, not the location: `Error::Replay`, not
  `Error::DecryptStep5Failed`.
- Constants for every number that appears in the spec, named after what the
  spec calls it: `HEADER_LEN = 81`, `PAD_BLOCK = 1024`, `MAX_BLOCKS = 63`.
  A bare `161` in code is a bug waiting for a spec change.

## 5. The SDD workflow

Code follows the spec, not the conversation. The order is fixed because each
step catches a class of mistake the next one cannot:

1. **Read** `docs/spec.md` §3, §4 and the feature spec `specs/NNN-*.md`. If the
   spec does not exist, write it from `specs/TEMPLATE.md` and stop for human
   review. Writing code against an unwritten spec is how two platforms end up
   disagreeing — and tests cannot be named (`sNNN_tTT_rRR`) until the
   requirements exist; never invent `R` numbers to get going.
2. **Red tests first.** One test per requirement, named `sNNN_tTT_rRR_*`, plus
   the negative vectors and the mutation table for formats. Watch them fail.
3. **Implement** the smallest thing that turns them green.
4. **Property and fuzz.** Every `parse`, `decrypt`, `open_*` gets a fuzz target
   and a round-trip property test (AGENTS 21). Every path that rejects input
   asserts `commits == 0`. Every stateful spec has a `FailingStore` test.
5. **CI green, then human review.** Commit messages start with `NNN:` and cite
   the requirement (`013: R4 random 24-byte nonce`). PRs are ≤ 400 net lines,
   one spec each.

When the implementation reveals the spec was wrong, do not quietly fix the code.
Add the question to `## Open questions` in the spec, and if the change touches
§3–§6 (wire format, keys, config, protocol), it needs an ADR — the CI
`adr-guard` will refuse the diff otherwise.

## 6. Dependencies

Every dependency is attack surface and a maintenance promise. Before adding
one: is it in `deny.toml`'s ban list (cryptographic crates outside libsodium,
compression, anything doing I/O in `core`)? Does it pull a tree you cannot
read? Could 40 lines of your own code do the job more clearly? Justify the
addition in the PR in one sentence. Dev dependencies count.

## 7. Review checklist

Use this when reviewing your own diff before opening a PR, and when reviewing
others'. A "no" on any line is a blocker in `core`, `store` and `server`.

- Does every change trace to a requirement `R*` in an accepted spec?
- Does every `R*` touched have a `T*` that fails without the change?
- Are all spec numbers named constants? Do offsets match §4 byte for byte?
- Does every rejection path write nothing (except the cursor)?
- Is there exactly one `commit` per logical operation?
- Do secrets live only in `Secret<N>` (or the platform equivalent) and never
  appear in logs, `Debug`, `toString`, error messages or test names?
- Is anything comparing fixed-size byte arrays with `==` instead of `ct_eq`?
- Could this be deleted, inlined or merged with something that already exists?
- Does a new comment explain *why*, and would a newcomer understand the code
  without it?
- Is the diff ≤ 400 net lines and about one spec only?
- Does the code read like the surrounding code? Same idiom, same density,
  same vocabulary. Consistency beats personal preference.

## 8. When in doubt

Prefer the boring choice. Prefer the choice that removes a case. Prefer the
choice a reviewer can verify by reading, not by running. And when two rules
here conflict, the one that keeps a secret safer wins.
