# Audit log

Findings and applied changes of every audit of the specification, newest first; `docs/spec.md` §13 points here and every PR that changes §3–§6 adds a row.

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

**Pending external review before the beta (spec 061):** derivations of §4 (contexts, tags, field order, encrypted header), `store` format (record, compaction, recovery), `ciborium` limits for untrusted payload, and the design of the epoch jump for v2.

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
