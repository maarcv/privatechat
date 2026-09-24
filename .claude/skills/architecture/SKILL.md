---
name: architecture
description: Project-wide architecture and code-quality standard for the private E2E chat (privatechat). Read this before writing, reviewing or refactoring ANY code in this repository, in any language — even for a "small" change, a test, a script or a one-line fix. It defines the layers and dependency direction (UI → Session → Channel → Store → crypto, dependencies pointing down), what "simple" means here, how errors and state are handled, naming, the SDD workflow (spec → review → red tests → code), the shape every client shares (state, intents, secrets, lifecycle, tests) and the review checklist. The language skills (rust, kotlin, swift, typescript-svelte) assume you have read this one.
---

# Architecture and code standard

This project is a group chat where the server is a blind mailbox and the client
is where security actually happens. The owner's mandate is
**uncompromising and simple**; everything below exists to serve it.

`AGENTS.md` is the rulebook: what is required, what is forbidden, and which CI
check enforces it. This skill explains *how* to write code that satisfies it.
When a rule is quoted below it is cited by number (AGENTS n), never restated;
if the two ever differ, `AGENTS.md` wins.

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
clocks or screens (AGENTS 10): it receives bytes and a `now`, and returns bytes
and events. The UI knows nothing about the protocol: it opens a TLS socket,
shovels frames in both directions, and renders what `Session` tells it. This
keeps the security-critical code testable without a device and identical on
three platforms.

The core boundary is AGENTS 20 (which types are opaque handles, which are
records, passwords as bytes, non-retention outside the core); the API itself is
`docs/spec.md` §9. Two design consequences:

- Boundaries carry **bytes and plain data**, never rich objects. A blob is
  `&[u8]`; `now` is `u64` milliseconds passed in.
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
order (`docs/spec.md` §9 for `core::Error`). Never fold two conditions into
one variant "for simplicity" — the negative test vectors need to tell them
apart.

Never panic on external data. In `core`, `store` and `server` the workspace
lints (AGENTS 4) make `unwrap`, `expect`, `panic!`, indexing and unchecked
arithmetic compile errors. A panic in the decrypt path is a remote crash.

**State lives in one place and changes in one commit** (AGENTS 23). Every
logical operation (receive a message, send a message, retire a key) becomes
exactly one `Store::commit(WriteBatch)`. A rejected message writes nothing
except the cursor, so its test asserts `commits == 0` with the cursor not
counted. `encrypt` reserves the counter *before* it returns a blob. If you are
writing to state in two places, you have invented a race.

**Time is a parameter** in `core` (AGENTS 10); `store` and `server` do their
I/O at one audited place each (`clippy.toml`). This makes TTL tests
deterministic and lets the fuzzer drive time.

## 4. Naming

- Names say what a thing *is* or *does*, in full words: `channel_id`, not
  `chid`; `decrypt_blob`, not `proc`. The only accepted abbreviations are the
  ones the spec itself uses as protocol literals (`pk`, `sk`, `mk`, `ttl`).
- Functions are verbs (`encrypt`, `retire_peer`), types are nouns
  (`WireMessage`), booleans read as predicates (`is_retired`, `has_more`).
- Test names encode traceability (AGENTS 6): `sNNN_tTT_rRR_<what_it_checks>`.
  Each client skill gives its spelling of the suffix; the prefix is what the
  checker reads.
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
   review (AGENTS 1). Writing code against an unwritten spec is how two
   platforms end up disagreeing — and tests cannot be named until the
   requirements exist; never invent `R` numbers to get going.
2. **Red tests first.** One test per requirement, plus the negative vectors and
   the mutation table for formats. Watch them fail.
3. **Implement** the smallest thing that turns them green.
4. **Property and fuzz** (AGENTS 21). Every path that rejects input asserts
   `commits == 0`; every stateful spec has a `FailingStore` test (AGENTS 23).
5. **CI green, then human review.** Commit and PR shape: AGENTS 7 and 14.

When the implementation reveals the spec was wrong, do not quietly fix the code.
Add the question to `## Open questions` in the spec; if the change touches the
wire format, keys, config or protocol it needs an ADR (AGENTS 3), and the CI
`adr-guard` refuses the diff otherwise.

## 6. Dependencies

Every dependency is attack surface and a maintenance promise. Before adding
one: is it in `deny.toml`'s ban list (AGENTS 2, 24)? Does it pull a tree you
cannot read? Could 40 lines of your own code do the job more clearly? Justify
the addition in the PR in one sentence (AGENTS 8). Dev dependencies count.

## 7. Client shape

The three clients are the same program in three languages: open a socket,
drive `Session`, render what it says, ask the platform keystore for a key.
Everything below holds for Kotlin, Swift and Svelte alike; each language skill
adds only the platform mechanics (versions, directories, platform APIs,
lifecycle hooks, test frameworks, linters).

**Layout.** Four layers, dependencies pointing inwards:

```
ui         views / composables / components. Render state, emit intents. No logic.
state      one state owner per screen (ViewModel, @Observable, .svelte.ts module).
platform   keystore, socket, files, clipboard, biometrics. The only code that
           touches platform APIs beyond the UI toolkit.
core       via uniffi or Tauri commands: opaque handles and records (AGENTS 20).
```

**State and intents.**

- One state union per screen (`Loading`, `Locked`, `Ready(data)`,
  `Failed(kind)`), owned by the state owner, read by the views.
- One intent union per screen and one entry point (`onIntent` / `send`).
  Every user action is greppable and testable.
- Views decide presentation, never trust: a view may colour a retired peer
  grey; it never decides whether a peer is retired — the core said so.
- Dependencies by constructor, wired by hand in one `AppGraph` at startup. No
  DI framework: the app has a dozen classes and the framework would be its
  largest dependency.
- Structured concurrency: every task belongs to a state owner or to the socket
  and is cancelled with it. Detached or unscoped tasks are bugs.

**Talking to the core.**

- The socket loop is a pure host for `Session`: read a frame → `onFrame(frame,
  now)` → apply the events → write whatever `outgoing()` returns. It never
  looks inside a frame. `now` is the platform clock, passed **into** the core.
- The storage key and the `.chatcfg` password are byte arrays: passed once,
  then filled with zeros in a `finally` / `defer` / `.fill(0)`. A string cannot
  be zeroed, so a password never becomes one.
- Secrets never reach a view as a string. The config QR is drawn from bytes
  the core returns; the password words are shown from a byte array and cleared
  when the screen goes away.
- Errors from the core are mapped to the screen's `Failed(kind)` once, at the
  state owner. Exceptions are for programming errors only.

**Views.**

- Stateless: state and callbacks in, nothing out. Local state only for
  transient visuals (scroll, hover, animation).
- Names: screens and rows are nouns (`ChannelScreen`, `PeerRow`); state
  `XxxState`; intents `XxxIntent`. One type per file; helpers used by a single
  screen live in that screen's file.
- Message lists are keyed by `serverId` and never re-sorted or filtered in the
  view: the core delivers order.
- Strings live in the platform resource files, English source plus the UI
  languages of `docs/spec.md` §12, never inline. Every icon has an
  accessibility label; a screen-reader pass once per screen.

**Lifecycle and device rules** are `docs/spec.md` §8, one row per platform:
lock or background → close the session, zero the key, drop the store; on
return, reconnect with the core's cursor; no background work, no push, no
third-party SDK. The socket is configured as in §6 "Transport".

**Testing.** Drive the state owner with intents and assert the state sequence;
platform classes have in-memory fakes; UI tests for exactly two flows (import a
config, verify a peer), not for every button; no test touches the network or
the real keystore. Test names carry the spec id where they cover a requirement.

**Tooling.** The platform linter and formatter run in CI and must be clean; no
suppression without a reason comment. Builds are reproducible (§8 "Code
integrity"); release signing happens in CI with the offline key.

## 8. Review checklist

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

## 9. When in doubt

Prefer the boring choice. Prefer the choice that removes a case. Prefer the
choice a reviewer can verify by reading, not by running. And when two rules
here conflict, the one that keeps a secret safer wins.
