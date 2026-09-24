# Audit log

Findings and applied changes of every audit of the specification, newest first; `docs/spec.md` §13 points here and every PR that changes §3–§6 adds a row.

## Audit F

**2026-09-24 — Audit F, second review of the phase 1 specs 011–017 after audit E, in the same three independent passes (A: completeness and SDD; B: adversarial cryptography; C: goal, simplicity, implementability).** One blocker, a regression introduced by audit E; nothing breaks confidentiality, the key hierarchy or encrypt-then-sign. Substantive changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| F1 | A stale message still advanced `max_counter` and raised no own-key alert: a thief could mint one with `counter = 2^64 − 2`, `sent_at = 0` and silence the victim everywhere, with no alert (F-B1, regression of C5) | Blocker | A stale message changes nothing but the cursor; from one's own key it still persists `OwnKeyUsedElsewhere` (ADR 0027, supersedes 0024; §4) |
| F2 | The stale rule ran after `validate`: a stale message with an unknown `type` became `Unreadable`, was persisted and could create and evict peers (F-B2) | Medium | Stale checked as soon as `sent_at` can be read, before the `type` check and `validate` (ADR 0027, §4) |
| F3 | A receiver clock ahead of the server by more than the TTL lost every live blob for good at step 2 (F-B4) | Medium | Step 2 carries the same 360 000 ms margin (ADR 0027, §4) |
| F4 | The mutation table could not prove what the signature covers: every mutation also broke the AEAD (F-B3) | Medium | Mutations must fail in `verify` itself; a narrower signed range is tested; a byte-by-byte mutation property (spec 013) |
| F5 | `export_encrypted` accepted any password, so the 77 bits rested on each UI (F-B8) | Medium | The export draws the password and returns it with the file (ADR 0028, supersedes 0026; §5, §9) |
| F6 | `export_qr` put `K_ch` in a `String`, against AGENTS 5 (F-A3) | Medium | The QR crosses the boundary as ASCII bytes the UI zeroizes (ADR 0028, §5, §9) |
| F7 | Only four whitespace characters were collapsed: a mobile keyboard's U+00A0 made the right password wrong (F-A20) | Low | Every run of Unicode `White_Space` collapses (ADR 0028, §5) |
| F8 | §4 literals froze on accepting 013 while the vectors froze at the phase 1 exit (F-A8) | Low | Both freeze at the phase 1 exit, after the reference script (§4) |
| F9 | The reference script could not check Ed25519, so nothing independent pinned the signed range or `pk_ch` (F-B6) | Medium | The script carries the RFC 8032 §6 reference Ed25519, standard library only (spec 015) |
| F10 | A key added in v1.x could make one signed blob read as two different messages across versions (F-B7) | Low | A new payload key never changes what keys 0–3 mean to v1.0 (§4) |
| F11 | Process rules written as requirements whose tests only grep files, and two fuzz targets that add nothing (F-C3, F-C4) | Medium | About 15 requirements removed or moved to acceptance; seven targets; AGENTS 21 becomes a set check with a named exclusion list |
| F12 | Nine one-hour targets in one job exceed the 6-hour runner limit (F-C5) | Medium | One parallel nightly job per target (§10) |
| F13 | `store` and `server` had no stated way to reach the crate-internal codec and crypto (F-A18, F-C13) | Low | Only through `pub` functions of `core` defined by 020 and 030, each with a fuzz target (§9) |
| F14 | `BadPadding` had no producer; `passphrase` and `password` mixed (F-A11, F-C14, F-C naming) | Low | `BadPadding` removed; `password` and `BadPassword` everywhere (§9, skills) |
| F15 | `server_url` could grow a path later only with a `config_version` bump (F-C) | Low | No path, now or later; self-hosters use their own host or subdomain (§5) |

The spec-level defects (the unreachable `Trailing` error and field-check order of 017, the unreachable version-mismatch rule of 011, the leftover fuzz dependency in the acceptance of 011 and 017, base64url and vector-generation ownership, PR slices, test paths and header inconsistencies) were fixed inside the specs and are not listed.

## Audit E

**2026-09-24 — Audit E, review of the phase 1 specs 011–016 before acceptance, in three independent passes (A: completeness and SDD conformance; B: adversarial cryptography and protocol; C: fit with the goal, simplicity and implementability).** 84 findings (E-A1–E-A37, E-B1–E-B17, E-C1–E-C30; the pass prefix keeps them apart from the top-level ids of audits A, B and C). None breaks the key hierarchy, domain separation, encrypt-then-sign or the strict Ed25519 verification. The substantive ones, grouped, and the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| E1 | CBOR through `ciborium` + `serde` brought about nine crates into `core`, the first external parser on the hostile path, and still needed a hand-written strict profile, integer-key serialiser, byte visitors and a two-step version read (E-A16, E-B11, E-C3, E-C14, E-C15, E-C16, 011-R17) | High | Own record encoding, `key` u8 ‖ `len` u32 BE ‖ `value`, strictly increasing keys, typed decoding, no dependency (ADR 0023, supersedes 0015); new spec 017-record-encoding; `core` keeps two dependencies (§4, §5, §6, §9) |
| E2 | `RetiredKey`, `PeerLimit` and `Replay` ran on an unauthenticated, bit-malleable header: the mutation table depended on receiver state and forged values could drive evictions, counters and false compromise alarms (E-A7, E-A8, E-B2, E-B9, E-C6, 013-R12) | High | Signature right after the header, before any state; no effect before it; every effect computed only for a consumed message (ADR 0024, §4) |
| E3 | Client expiry trusted the server's `received_at`: a malicious server could deliver an expired blob months later as new (E-B1) | High | A consumed message with `sent_at + ttl_ms + 360 000 < min(received_at, now)` is discarded as `Expired` (ADR 0024, §4, §6) |
| E4 | Phase 1 specs required the `Store`, cursor, peers, events and identity regeneration of phase 2, and had no pure whole-message entry point to fuzz or to generate vectors from (E-A2, E-A3, E-A5, E-A6, E-A14, E-C1, E-C5) | High | 013 defines pure `seal` (nonce as a parameter), `verify` and `open`; an authentic but unreadable message is `Ok(Unreadable)`; persistence moves to 021, 022, 024 and 025; phase 1 vectors carry no `commits` (specs 012–014, `specs/vectors/README.md`, §10 DoD) |
| E5 | 011–014 read vectors produced by 015, which depended on them (E-A4, E-C2) | High | 015 implemented right after 010; phase 1 order 010 → 015 → 017 → 011 → 012 → 013 → 014 → 016 (§10) |
| E6 | The 12 words needed SHA-256 for the BIP-39 checksum, absent from §4 and from spec 010 (E-A12, E-B13, C, 014-R12) | Medium | Words = first 132 bits of `fp` over the BIP-39 list, no checksum, not a mnemonic (ADR 0025, §4, §12) |
| E7 | `privatechat/fp/v1` is 17 bytes: the fingerprint input is 65 bytes, not 66 (E-A11, E-B3) | Medium | Corrected in spec 014; every spec asserts the length of its tags |
| E8 | The 7-word password had no owner and no byte encoding: cross-platform imports could fail, and UI generation put randomness outside libsodium (E-A15, E-B4, E-C12) | Medium | Generated by `core`, canonical bytes, canonicalised on open (ADR 0026, §5) |
| E9 | Optional invitation expiry with defaults, a `None` meaning never, and a stored config that could expire after import (E-A17, E-C11, E-C17) | Medium | Fixed expiry per form, no parameter; dropped once imported (ADR 0026, §5) |
| E10 | Raw binary config QR needs a different raw-byte scanner API per platform (E-C26) | Low | QR is base64url text of the record, no prefix, no scheme (ADR 0026, §5) |
| E11 | "No Cc/Cf" named no Unicode version: two app versions could disagree on whether a message is readable (E-B5, E-C15) | Medium | Only Cc (a fixed set) is checked; an invalid `display_name` is dropped, never makes a message unreadable; Cf removed on rendering (§4) |
| E12 | Derived vectors were produced by the implementation under test, so a derivation bug would be frozen as the reference (E-B6, E-C8) | Medium | Independent reference script with the Python standard library before freezing; exception in AGENTS 2 (spec 015, §11) |
| E13 | Vectors froze on first commit: a phase 1 bug would force `proto_version = 2` before v1 exists (E-C7) | Medium | Freeze at the phase 1 exit; before that, `adr-not-needed` plus the reviewer's reason (AGENTS 18) |
| E14 | u64 counters as JSON numbers do not survive Kotlin, Swift or 2^53-limited parsers (E-A18, E-C9) | Medium | 64-bit integers as BE64 hex in the vector files (`specs/vectors/README.md`) |
| E15 | The generator writing files contradicted AGENTS 4 and 10 literally, and "byte-identical" was checked once by hand (015-R5, E-C recommendation 3) | Low | Narrow exception named in AGENTS 4 and 10; an always-run test compares generated and committed files (spec 015) |
| E16 | Fuzz targets missed the post-signature path, `open_encrypted` and the verify QR; the fuzz crate cannot reach crate-internal functions; `arbitrary` unused (E-A20, E-A22, E-A23, E-B7, E-C3, E-C20) | Medium | `cfg(fuzzing)` entry module, signed-input and after-KDF targets, lint-table equality test, `libfuzzer-sys` only (spec 016) |
| E17 | No spec created `core::Error`; `OutOfMemory` from Argon2id could only surface as "wrong password" (E-C4) | Medium | Spec 011 creates the hand-written `Error` with a new `Internal` variant (§9) |
| E18 | The UI could build a `key_retired` or its own `sent_at` through a public `Payload` (E-C13) | Medium | `Channel::encrypt(body, display_name, now)`; `Payload` crate-internal (§4, §9) |
| E19 | `Config` exposed only `host()`: channels on one host and different ports would share a `Session`, and the UI could not open the socket (E-C10) | Medium | Accessors `server_url`, `suggested_name`, `ttl_seconds`; grouping by host and port (§9) |
| E20 | A decrypt verdict could leak through `on_frame` errors or reconnect timing (E-B16) | Low | No-oracle rule extended (§4) |
| E21 | `adr-guard` protected specs 011–013 only; the phase 1 CI line listed a log test no phase 1 spec carries (E-A26, E-A32) | Low | Guard extended to specs 011–014 and 017 (`ci.yml`, §10); log test deferred to spec 100 (§10) |

Test naming, requirement coverage, RFC 2119 wording, glosses and the other minor findings were applied inside the specs and are not listed.

## Audit D

**2026-09-20 — Audit D, coherence review of the whole documentation (spec, threat model, ADRs, `AGENTS.md`, skills, feature specs, CI).** Contradictions, duplicated owners and stale references; wording-only fixes are not listed. Substantive changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| D1 | §2 gave the network observer "a single connection" while §6 and ADR 0022 have one connection per server; §4 and §6 restated what the server sees | Low | §2 row "User's network observer": one connection per server (does not reveal the number of channels on it); §2 row 1 owns the server's view, §4 and §6 point to it (§2, §4, §6, `docs/threat-model.md`) |
| D2 | Definition of done in three places (§10, PR template, AGENTS 9) with different items and wording | Medium | §10 owns the 12 items; the PR template renders exactly them as checkboxes; AGENTS 9 points to §10 |
| D3 | `Settings` was a boundary object in the §9 API but missing from every opaque-handle list (§8, §9 table, AGENTS 20, skills, bindings READMEs) | Low | One shared sentence — `Config`, `Channel`, `Session` and `Settings` opaque handles; `Received`, `Peer`, `Fingerprint`, `Gap`, `Event` the only `Record`s — in §9, AGENTS 20 and the skills; the other places point to §9 |
| D4 | §4 said `encrypt` commits `counter + 1` and the blob "before deriving `mk`": the blob cannot exist before its key | Medium | Ordering restated: reserve `counter`, derive `mk`, seal, commit `counter + 1` with the blob, return; no blob leaves before the commit (§4) |
| D5 | The `unsafe` rule differed between AGENTS 12, spec 000 and the rust skill (`forbid` everywhere vs an FFI exception) | Medium | One wording: `forbid` in `store` and `server`; `deny` in `core` with `allow` only in `crates/core/src/crypto/ffi.rs`, `// SAFETY:` on every block (AGENTS 12, spec 000, rust skill, `Cargo.toml`) |
| D6 | The crate ban (AGENTS 2) was scoped to `core` while `deny.toml` bans across the workspace; spec 000 named no crate | Medium | Ban stated for the whole workspace with the literal list of `deny.toml`; `proptest` (and `rand`) only in `[dev-dependencies]` (AGENTS 2, spec 000, `s000_t08`) |
| D7 | `adr-guard` described with different triggers in AGENTS 18, §10 and the rust skill | Low | One wording: a diff that touches `specs/vectors/` or the protected paths of §10 without a new ADR file fails, unless a human sets `adr-not-needed` (AGENTS 18, §10, skill) |
| D8 | The audit log lived in §13 of the spec: the longest section, target of every "row in §13" pointer, and the doc lint had to cut it out | Low | Moved to `docs/audit-log.md`; §13 is a two-line pointer; every reference (spec header, §10, §11, ADR TEMPLATE and README, ADR 0013, PR template, SECURITY.md) updated; the lint scans the spec whole |
| D9 | Specs 000–003 were implemented while still `in review`, against the "acceptance precedes code" rule | Low | `specs/README.md` records that phase 0 was bootstrapped with implementation and review in parallel; from spec 010 on, acceptance precedes code |
| D10 | ADR 0014 wrote `expires_at = received_at + ttl_seconds` and `min(received_at, now_local) + ttl_seconds`: the C8 unit mix survived in the ADR | Medium | Unit-free wording that points at the §6 formulas (ADR 0014) |
| D11 | Stale references in accepted ADRs: "link with a fragment" (0001), the compromise alarm as the response (0004), `pk` in the clear (0005), collapsing unknowns (0006), dead consequences (0011), identity export (0013), `open_store` (0020), a vanished §12 risk (0017), "app configuration" and "050–052" (0022), UI flow restated (0016) | Low | Minimal edits limited to the stale reference in each ADR; decisions unchanged |

## Audit C

**2026-09-20 — Audit C, technical review in three independent passes (adversarial cryptography; privacy and traffic analysis; implementation and operations red team).** 33 attacks tried against §4 with none that breaks confidentiality or authenticity; findings and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| C1 | `sender_pk` in the clear + `publish` bound to the connection gave the server the `IP ↔ pseudonym ↔ channel ↔ time` record of every message | High | Header encrypted with `K_hdr` (ADR 0018): 40 B XOR, identical size, zero server changes |
| C2 | The anti-replay promise only held for stateful receivers: an intruder could re-inject old blobs to new members or to ones who had not seen them | Medium | Strictly increasing counter, no window; total order on the server; one key one device (ADR 0019) |
| C3 | 55-bit file password for a secret that does not rotate, with a perfect oracle; and the risk of lowering Argon2id | Medium | 7 words (77 bits) + Argon2id INTERACTIVE: stronger and works on every device (§5) |
| C4 | Wrapping key invalidation on biometric enrolment = loss of all data for nothing in return | High | `setInvalidatedByBiometricEnrollment(false)`, `.userPresence`; key loss documented (§8) |
| C5 | No rule for valid messages from one's own key: a thief could leave the victim mute forever without warning | High | Send counter bump + banner "Someone has written with your key"; it is the only compromise detector (§4, §7) |
| C6 | `Store` outside the core (Room, GRDB): three transactions, DB key in a JVM/Swift `String` | High | A single `Store` in Rust with a single `commit(Batch)`; Kotlin and Swift never touch the storage (ADR 0020; format in ADR 0021) |
| C7 | Send counter persisted "after" the blob: crash → `counter` reuse and silent rejection by everyone | Medium | `encrypt` reserves the counter and writes `outbox` in a single commit before encrypting (§4) |
| C8 | Three formulas mixed ms and seconds: TTL 1 000× shorter if implemented literally | Medium | `ttl_ms` defined; no formula mixes units (§4, §6) |
| C9 | Unprotected arithmetic (`max − W` underflows for every new peer) and no lint | Medium | `arithmetic_side_effects` at `deny`, `overflow-checks` in release, `saturating_sub` (§4, §10, AGENTS) |
| C10 | The API of §9 could not implement §6: the WS state machine would have been written three times | Medium | Sans-I/O `Session` in the core; `acked`, `outbox`, `cursor` (§9, ADR 0020) |
| C11 | Reconnection cursor as an oracle (it revealed which blobs the client rejects) and `since` in exact ms as a cookie | Medium | Cursor = last processed `push` whatever the result; `since` rounded to the minute; random `client_ref` (§6) |
| C12 | Payload rules insufficient for a fuzzer and three platforms; "unknown type consumes" but "malformed CBOR does not" | Medium | Authenticated = consumed; `Unreadable`; `serde` into a struct; numeric limits; single `validate()` (§4) |
| C13 | Step 1 of §4 with a single error for three conditions: negative vectors without a unique result | Medium | One `Error` per condition; mandatory mutation table in TEMPLATE (§4) |
| C14 | Ten unspecified server behaviours (non-unique `received_at` → infinite pagination, 64 MiB frames, slowloris, purge, single writer, `Host` vs `public_host`) | Medium | All fixed in §6 |
| C15 | Per-IP quotas incompatible with Tor and NAT; `K_rot` theatre; "50 new channels/hour" required the IP→channels map the spec denies | Medium | Per-IP limits only before authenticating; no `K_rot`; `127.0.0.1` exemption (§6) |
| C16 | "One connection per channel by default" was theatre without Tor and leaked the number of channels to the ISP; TLS resumption and `User-Agent` linked connections and revealed the platform | Medium | One connection per device; circuit per channel only with SOCKS5; no TLS resumption; fixed UA; no `permessage-deflate` (§6) |
| C17 | Missing adversaries: seized operator, hosting provider, member-operator, post-deletion forensics, badly described network observer | Medium | Six new or rewritten rows in §2; §1 says "without Tor, an IP is a person" |
| C18 | App "PIN or biometrics" without defining what it protected: decorative PIN or offline brute force | Medium | No app PIN; the lock is the system prompt (§8) |
| C19 | In-memory blob queue while locked: OOM and state outside the `Store` | Medium | Locked ⇔ disconnected (§8) |
| C20 | `sent_at` in ms = clock fingerprint that links regenerated keys and identifies devices | Medium | Rounded to the minute (§4) |
| C21 | The spec depended on libsodium's strict Ed25519 verification without writing it down; the server could use another verifier | Medium | Written in §4; the server verifies via `core::crypto`; negative vectors for small order and non-canonical S (§4, AGENTS) |
| C22 | Retired peers purged after the TTL: the dead key resurrected as unknown | Low | The `(pk, retired_at)` records are never purged (§7) |
| C23 | 44-bit short identifier collidable in ~200 GPU-days nullified label disambiguation | Low | Collision rule: show the 12 words of both with a warning (§4) |
| C24 | Encoding ambiguities (`[0..16]`, LE of `subkey_id`, `id=1` vs `id=0`, unnormalised `host`, double `config_version`); no-compression not written down | Low | All fixed in §4, §5, §6 |
| C25 | Simplification: identity export, `compromise_alert`, `presence`, `reply_to`, `join` link, connection-sharing option, tombstones, collapsing of unknowns, negotiable `limit`/`max_blob_bytes`, double derivation `K_send`/`mk` | — | All removed from v1 without losing any guarantee of §1; a single message-key derivation; two forms of invitation; two payload types. ADR 0011 deprecated |
| C26 | Device leaks not written down: third-party telemetry, window title, WebView, clipboard histories, Lens, desktop keychain | Low | New rows in §8; §1 and §5 corrected |

**Later decision (2026-09-20, same day):** the client carries no database; storage is encrypted files with atomic commit in pure Rust (ADR 0021). Removes SQLCipher, OpenSSL and the exception to the "libsodium only" rule. The server moves from `sqlx` to plain `rusqlite`.

**Pending external review before the beta (spec 061):** derivations of §4 (contexts, tags, field order, encrypted header), `store` format (record, compaction, recovery), the record codec limits for untrusted payload (ADR 0023), and the design of the epoch jump for v2.

## Audit B

**2026-09-20 — Audit B, three independent passes (cryptography and protocol; device, server and trust UX; coherence of the SDD process).** 88 findings; changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| B1 | The symmetric ratchet gave no forward secrecy: `k_0` is recomputed from `K_ch`, present on every device | High | Direct message-key derivation; §1 promise corrected; ADR 0013 supersedes 0003; ADR 0004 clarifies that FS and PCS arrive together in v2 |
| B2 | It was not defined which bytes were signed; "canonical CBOR" is not guaranteed by `ciborium` | High | Fixed-size binary envelope with offsets; CBOR only in the payload; domain tags (§4, ADR 0015) |
| B3 | 66-bit fingerprint and a UI that showed 22 of them (2 words) as identifier | High | 12 BIP-39 words with checksum or QR with `pk_u`; 4-word short identifier marked as non-verification (§4, §7) |
| B4 | "Maximum jump 10 000" desynchronised a sender forever; 64-key window ambiguous | High | Sliding window (revised in C2: strictly increasing counter) |
| B5 | "Lowest TTL wins" let anyone with the config destroy everyone's retention | High | TTL inside the `channel_id`; per-message expiry; no channel table (§4, §6, ADR 0014) |
| B6 | `publish` without authorisation; no quotas; per-connection rate limit not sybil-resistant; `channels` table of unbounded growth | High | `publish` bound to the connection's subscription; envelope validation; quotas (§6) |
| B7 | After regenerating or stealing a key, the old one remained "Alice ✓" indefinitely | High | `key_retired` message, Retired state, manual action (§4, §7, ADR 0016) |
| B8 | The defence against "I changed phone" depended on `display_name` and on a short fingerprint collidable in seconds | High | Labels not reusable without verifying; confusables normalisation; `verify:` QR defined; pre-verification (§7) |
| B9 | A member on the hosted web client made the confidentiality of the whole channel depend on the web operator | High | No hosted web in v1; Tauri desktop (ADR 0017) |
| B10 | ADR 0003 with a formula different from §4; §9 API without `Result`; anti-replay spread across three specs; AGENTS with outdated spec ranges | High | ADR 0003 superseded; API with `Result` and `Config::create`; spec 012 owns anti-replay, 026 the peer limits; AGENTS references §10 |
| B11 | Rule "no other cryptographic library in the project" impossible to meet (SQLCipher, TLS) | High | Rule scoped to `core` with a list of forbidden crates (AGENTS 2, ADR 0002) |
| B12 | Authentication signature without domain prefix or encoding; nonce without semantics | Medium | `privatechat/auth/v1` tag, `BE32(ttl)`, `host` inside the signature, per-connection 60 s nonce (§6) |
| B13 | Encrypted config with Argon2id parameters in the header (DoS via `memlimit`); user-chosen password | Medium | Fixed `PCFG` format, parameters bound to `config_version`, app-generated password (§5) |
| B14 | `reply_to` undefined; phantom types in the enum; no rule for unknown types | Medium | Closed v1 enum; unknown type = consumed (§4) |
| B15 | Periodic `presence` = free traffic analysis | Medium | Only on explicit actions (removed altogether in C25) |
| B16 | Config QR as a URL; clipboard synced to iCloud; 24 h QR expiry | Medium | QR without URL scheme, 10 min by default; `localOnly`; `EXTRA_IS_SENSITIVE` (§5, §8) |
| B17 | Multiplexed connection gives the device↔channels map that A6 deemed unacceptable | Medium | One connection per channel by default (revised in C16) |
| B18 | "Do not log IPs" unenforceable with proxies and default logs; backups nullify the TTL | Medium | `trusted_proxies`, reference configs, no backups of `messages`, `secure_delete` (§6) |
| B19 | DB key on the device badly specified | Medium | Random wrapped key; life cycle defined; no background (§8) |
| B20 | Duress code mandatory in §8 but "physical coercion" outside the model in §2; legal risks | Medium | Out of v1; coercion inside the model only as damage limitation (§2, §8) |
| B21 | 500-peer limit exhaustible by an intruder, leaving legitimate members invisible | Medium | 500 labelled (hard) + 50 unknown with LRU eviction; never silently (§7) |
| B22 | Alarms spammable by unknowns; repeatable social blocking; "Leave channel" undefined | Medium | Grouping and limits (type removed in C25); "Leave" defined (§7) |
| B23 | `since`/`server_id` without semantics; `gaps()` with false positives after being offline | Medium | Random `server_id`, cursor by `received_at`, `oldest_retained_at` (§6) |
| B24 | Homonymous `spec/vectors` and `specs/` directories; `sodium_memzero` vs `zeroize`; "or" in places of decision; "for example" in limits | Medium | `specs/vectors/`; one mechanism per platform; fixed values (§6, §8, §9) |
| B25 | External review required in phase 1 and at the same time "before the beta"; weekly plan contradicted the phase order | Medium | Internal in phase 1, external in phase 6; MVP after phase 4 (§10) |
| B26 | Spec TEMPLATE without dependencies, acceptance criterion, security, vectors or history; ADRs without template, index or state vocabulary | Medium | `specs/TEMPLATE.md` extended; `docs/adr/TEMPLATE.md` and `README.md`; fixed states |
| B27 | AGENTS without rules on language, `unsafe`, TODO, I/O in the core, PR size, ignored tests, generated code, vectors | Medium | Rules 11–20 (AGENTS.md); workspace lints in the Definition of done |
| B28 | Cosmetics: pre-A1 file name of ADR 0010, "12 sections", non-literal §3 titles, incomplete threat-model, "padding to fixed size" | Low | Corrected everywhere |

## Audit A

**2026-09-19 — Audit A, internal in three passes (cryptography and protocol, device and operations, SDD process).** Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| A1 | HMAC authentication required the server to know `K_auth` and it was not said how it obtained it | High | Channel Ed25519 key pair derived from `K_ch`; the client signs the nonce; the server only has `pk_ch`. Self-certifying `channel_id` (§4, §6, ADR 0010) |
| A2 | `K_send` was derived with an ad hoc XOR | Medium | Keyed BLAKE2b hash (§4; merged into a single derivation in C25) |
| A3 | No replay rule or counter jump limit | High | Monotonic counter per `pk`, rejection of duplicates (§4; revised in B4 and C2) |
| A4 | Exporting `sk_u` without the counter allows reusing `mk_i` | High | The counter travels with the exported key (feature removed in C25: one key, one device) |
| A5 | No peer limit per channel: storage DoS with the config | Medium | `pk` limit per channel; spec 026 (§4, §10; revised in B21) |
| A6 | Push with a per-channel token recreates the device↔channels map on the server | High | No push in v1; open decision for v2 (§8, §12) |
| A7 | The server can delete or delay messages without detection | Low | Documented in the threat model; the client shows `counter` gaps (§2, §6) |
| A8 | `sent_at` not verifiable | Low | Order by `received_at`; warning if they differ by more than 5 min (§6) |
| A9 | Clipboard clearing not guaranteeable on iOS | Low | Marked as best-effort (§8) |
| A10 | `docs/threat-model.md` referenced but nonexistent | Low | Created as an extract of §1, §2 and §6 |
