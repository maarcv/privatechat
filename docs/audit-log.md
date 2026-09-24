# Audit log

Findings and applied changes of every audit of the specification, newest first; `docs/spec.md` §13 points here and every PR that changes §3–§6 adds a row.

## Audit I

**2026-09-24 — Audit I, fourth review of the phase 1 specs 011–017 before acceptance, in four independent passes (I-A: order and coherence of the set against `docs/spec.md`, the ADRs and the code; I-B: simplicity against the promises of §1 and the threats of §2; I-C: technical viability under the pinned toolchain, libsodium and the workspace lints; I-D: end-to-end scenarios walked as a user and as each device).** No Blocker: no byte on the wire, no key derivation and no ADR decision changes. Pass B found the phase 1 scaffolding doing the same work twice and phase 2 concerns specified a phase early; pass D found the phase 2 seam and two product truths the specs implied but never said. The human reviewer decided the simplifications (I1–I8) and the phase 2 seam items (I10); the viability corrections (I9) are wording. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| I1 | The same vector bytes had three producers: a Rust generator, the Python reference script recomputing them and an always-run equality test between the two, with a registry, three AGENTS exceptions and generator-only seams behind them (B1) | High | One producer: `scripts/reference/vectors.py` produces every `specs/vectors/NNN.json` from fixed inputs and the Rust tests reproduce them through `check_all`; no generator, no `SECTIONS`, no equality test, no `disallowed_methods` allow; `chatcfg_reference` becomes `pinned` from a Rust test's bytes; wording in AGENTS 2, 4, 10, 15, 18, §4, §9, §10, §11 and specs 011–015, 017 |
| I2 | Twenty tests read the Rust source as text to prove what `pub(crate)`, a private constructor or an absent `impl` already prove, and grew their own `SOURCES` registry and CI step (B3) | High | Visibility, absent trait impls and signatures move to `## Interface` and get no T*; every source-scan clause deleted; 015 R15/T15 and `SOURCES` gone; AGENTS 6 says the compiler enforces them; spec 010 keeps its tests |
| I3 | `cargo deny` over the fuzz crate, which never ships, dragged in a licence exception, a `jobserver` wrapper for `getrandom`, a lockfile copy and a `-D checksum-mismatch` step, and ran with cargo-deny's default config anyway (B2, C1, C5) | High | No `cargo deny` over the fuzz crate; `crates/core/fuzz/Cargo.lock` committed, `publish = false`, own `[workspace]` table, `.gitignore` for its outputs; the two `deny.toml` edits spec 016 prescribed (a `jobserver` wrapper for `getrandom` and a `libfuzzer-sys` licence exception) are never made (spec 016 R11, R12, T09, T11) |
| I4 | Spec 017 implemented and fuzzed `bool`, nested records and lists that no phase 1 record uses, plus a "partial read" mode that re-decoded bytes one in-order `Reader` already decodes (B4, B5, C11) | Medium | 017 implements `u8`, `u32`, `u64`, `bytes`, `bytesN`, `text`; 020 and 030 add a type when their first schema needs it; §4 keeps the full type list as the format and says what phase 1 implements; no partial read: 011 R3 and 013 R12 say when the version and stale checks run; the test schema is written like production code |
| I5 | Spec 012 carried the counter, gap, retention and own-key verdicts of phase 2, a five-parameter function with three booleans, and three functions for one keystream of 104 bytes (B6, B7) | Medium | 012 is keys and header: derivations, `message_key`, the header, `header_keystream` and its vector; the verdicts, `signature_retention_end` and the own-key rule move to spec 021 next to the state they read; `KEY_RETIRED_COUNTER`, `EXPIRY_MARGIN_MS` and `ttl_ms` are defined in 013; §4 "Anti-replay" points at 021 |
| I6 | The strict Ed25519 negatives of spec 010 were re-wrapped inside envelopes one layer up, and the template still demanded a negative vector for every rejection while the README had narrowed the rule (B8, A1) | Medium | The five vectors leave 013; TEMPLATE.md and the vectors README state the one rule: a rejection the primitive wrapper already proves is not repeated one layer up |
| I7 | The `server_url` grammar carried label, all-digits, IPv4 and leading-zero rules beyond what audit F decided, and neither it nor the password bounds were recorded as decisions (B9, A13) | Medium | Host of one or more bytes of `a-z`, `0-9`, `-` and `.`, bounded by the URL alone (a second bound of 253 bytes could not be reached under 256 and was dropped), port in 1..=65535 not 443, at most 256 bytes in all, nothing else (spec 011 R5, T05, vectors); both rules recorded in §12 as decided without an ADR; §5 summarises the grammar |
| I8 | Pull-request slices written as requirements and tests, loader fixtures testing `cfg(test)` code on inputs it never sees, and five copies of the "every vector is checked" requirement (B10, B11, B12) | Medium | 015 R13/T13 removed and slice sentences out of the tests; 015 R1, R2, R3, R5 merged with one positive test; one Interface sentence per spec for `sNNN_vectors_dispatch`; the script section of each spec becomes its own requirement |
| I9 | Viability: `Fingerprint` with fixed-size arrays could not be the uniffi `Record`; "reached by a target" had no operational rule; the nightly workflow installed neither cargo-fuzz nor the dated nightly; 013 R4 needs a concatenation buffer; 010 did not forbid the `minimal` feature that drops `crypto_stream_xchacha20`, lagged two planned additions, kept an open question with a T id and named specs by number; 011 left the header check and the password bounds unordered (C2, C3, C4, C6, C7, C10, C12, D13, A2, A3, A4, A10) | Medium | `Fingerprint { words: Vec<String>, short: Vec<String>, qr }` with lengths guaranteed by `presentation`; 016 R6 textual rule and exclusion file, R9 install steps; 013 R4 buffer sentence; 010 R16/T25 forbid `minimal` and `fetch-latest`, Interface lists `copy_from`, the loader note, `random_bytes` with its `Result`, question 010-R3 closed, `NNN-name` headers; 011 R13/R15 order fixed |
| I10 | Phase 2 seam and product truths: no self-backup after losing every device, one's own old key reappearing as an impostor, `pk_u` drawn only "when importing", no call for one's own fingerprint and `PeerId` undefined, the own `display_name` with no storage home, the fate of `outbox` entries under a retired key undefined, the gap exception with no named state, the own message's log record unwritten, two devices of one person unnamed, "re-importing and regenerating" read literally, a `key_retired` from an unknown key at the peer limit described twice, and ADR 0011 still naming a CBOR key (D1–D6, D8, D9, D11, D12, D14, D17, A7) | Medium | §1: re-import needs a fresh invitation, what comes back and what does not, two devices are two members; §4: `(pk_u, sk_u)` drawn at the first `Channel::open`, ordinary entries under the retired key stay and go out before the `key_retired`, the own record deferred to 020/021, `PeerLimit` clause; §5, §6 gap `None`; §7: the lost-key branch, the second device, the own `display_name` in `state.bin`, the device change reworded; §9: `PeerId` defined, `Channel::own_fingerprint()`, `encrypt` stores the name; ADR 0011 "CBOR key" → "payload key" as a stale-reference correction |
| I11 | Editorial: the §4 gap formula read as an overflowing `max_counter + 1`; §10 said "specs 010–016" and the §11 tree missed `fuzz_seeds.py`; the audit H preamble said three confirmation rounds; a missing blank line before "## Security" in 013 (C8, D15, A6, A9, A11) | Low | `saturating_add` in §4; "010–017" and the script names in §10/§11; "thirteen confirmation rounds"; the blank line |
| I12 | Reversed from audit H: H53, H57, H60, H62 (the fuzz `cargo deny` line: the `jobserver` wrapper, `-D checksum-mismatch`, the uncommitted fuzz lockfile and its CI copy) | — | Undone by I3; the fuzz crate commits its lockfile and runs no deny step, and `deny.toml` keeps the compression bans and the wrappers of H58, H59 and H61 |

Not changed on purpose: `encrypt` still returns the blob while `outbox()` is the publish path (D10) and whether a `Session` may hold zero channels for the create-time `hello` probe (D16) are left to specs 027 and 028; the Low items B15–B19 (two password bounds, two word-list digests, `host()` in phase 1, the four header checks, canonical QR bits) are not applied; ADR 0034 is not edited, since the fate of ordinary `outbox` entries (D6) is written in §4 and §7 and is consistent with it; `open` does not bind the payload `type` to the counter (D7): a `text` at 2^64 − 1 or a `key_retired` at an ordinary counter comes only from a non-conforming signer, and the receive side stays a pure function of the bytes. Renumbering: spec 015 R13 and R15 removed (R10 → R3, R14 → R6), spec 016 R2 moved to the Interface (R3–R13 → R2–R12), spec 017 R5, R6 and R16 removed (R17 → R14), spec 012 rewritten (R1–R8), spec 014 R6 removed (R7–R9 → R6–R8); the ADRs 0019, 0027, 0029 and 0033 no longer list spec 012 among their affected specs, and ADR 0023 says the reference script produces the vectors, stale-reference corrections under the `docs/adr/README.md` rule.

## Audit H

**2026-09-24 — Audit H, third review of the phase 1 specs 011–017 before acceptance, in three independent passes (H-A: completeness and SDD conformance; H-B: adversarial cryptography and protocol; H-C: fit with the goal, simplicity and implementability).** 53 findings in the first round (H-A1–H-A20, H-B1–H-B9, H-C1–H-C24), and thirteen confirmation rounds after it (rounds 2–14). None breaks the key hierarchy, domain separation, encrypt-then-sign, the verification order or the strict Ed25519 verification; the own-key alert, the leak of who writes and two holes in key retirement needed ADRs, and two smaller format decisions were taken with the human reviewer (ADRs 0029–0034). Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H1 | A message from one's own key with a counter below the send counter was taken as the echo, so a thief could write to later members with a low counter, or win the race for a counter sealed offline, and the alert never fired; at send counter 0 the rule was undefined (H-B1, H-B5) | High | Echo only when the signature equals one this device sealed (ADR 0029); one's own key has no `max_counter` (§4, spec 012 R11, spec 013 `Verified::signature`) |
| H2 | No round-trip property test for `Config::parse`, `parse_qr` or the file, and none for `parse_verify_qr`: specs 011 and 016 each pointed at the other (H-A1, H-C1) | High | Spec 011 R24; spec 014 T03 as a proptest; spec 016's exclusion list cites R24 |
| H3 | `Config::create`, which draws `K_ch`, had no requirement and no test (H-A2, H-C8) | High | Spec 011 R23 |
| H4 | The PR slices put the vectors in the last slice while earlier slices' tests read them; 015, 016 and 017 had no slice plan and exceeded 400 lines (H-A5, H-A6, H-C5, H-C6) | High | Spec 015 R13: each slice carries its vectors and dispatch arms; slices in 011 (five), 013 (four), 015, 016, 017 |
| H5 | The fuzz tests could not build: `cargo test` never sets `cfg(fuzzing)`, `cargo fuzz` needs nightly while the toolchain is pinned stable, the set check could never see the pub parsers, and the test schema was inside a `cfg(test)` module (H-A10, H-A17, H-C9, H-C10, H-C12) | High | `fuzz_entry` under `cfg(any(test, fuzzing))` with its tests in `core`; a dated nightly only in the fuzz workflow (spec 016 R10, rust skill); the set check counts calls through `fuzz_entry`; `record/test_schema.rs` |
| H6 | The reference script could not see the XChaCha20 compositions (key, nonce and associated data of the AEAD and of the header), so such a bug would be frozen as proto v1; its coverage list in 015 disagreed with the format specs and could not pass before they landed (H-B2, H-A3, H-A12, H-C2, H-C17) | Medium | The script carries ChaCha20, HChaCha20 and Poly1305 and recomputes `enc_hdr`, the ciphertext and the signature of every positive 013 vector; each format spec owns its list; every positive `derived` vector is recomputed or excluded by name (spec 015 R11, R12; specs 011, 012, 013) |
| H7 | A blob dated far in the future never became stale, so a server could revive it without limit (H-B4) | Low | Stale also when `now + ttl_ms + 360 000 < sent_at` (ADR 0030, §4 step 7, spec 013 R12) |
| H8 | The `.chatcfg` length gave away the length of `server_url` plus the name (H-B9) | Low | The record is padded to 1 024 bytes; every file is 1 085 bytes (ADR 0031, §5, spec 011 R13) |
| H9 | Fuzz seeds had no input layout, no fixed keys and no writer, so they died at `WrongChannel` (H-A9, H-B7, H-C13) | Medium | Exact layouts and the keys of the 013 vector `text_k1`; `scripts/fuzz_seeds.py`, corpus not committed; T06 as a property (spec 016 R5, R6, R9) |
| H10 | The vector schema had no booleans, lists or absent values, and text could not be told from hex (H-C4) | Medium | Typed values and a fixed set of text fields (`specs/vectors/README.md`, spec 015 R3 and its `Value` API) |
| H11 | The dispatch rule made spec 010's `load` calls illegal (H-C3) | Medium | Spec 010 keeps `load` and is exempt from spec 015 R10 |
| H12 | §4 typed `display_name` as `text` while spec 013 reads it as bytes so that a bad name never fails the message (H-A7) | Medium | §4 says `bytes` |
| H13 | Spec 011 R20 required every function of `proto` to return `core::Error` while the codec of 017 returns `RecordError`; the `CryptoError` helper was partial (H-A8, H-C7, H-C21) | Medium | `RecordError` never leaves `proto`; the helper maps every variant (spec 011 R18, R20) |
| H14 | The worked example made a case of T15 impossible (H-A4) | Medium | Example and test corrected (spec 013) |
| H15 | Several rejections of external input had no negative vector, while crate-internal tables and `seal` rejections were vectors no platform reads (H-A11, H-C16) | Medium | The README rule covers external input only; new negative vectors in 011 and 017; the counter tables of 012 and the `seal` cases of 013 become unit tables |
| H16 | CI work lived only in acceptance prose, and every implementation PR would trip `adr-guard` (H-C11, H-C15) | Medium | Spec 015 R14 and spec 016 R13 name the steps; §10 states the `adr-not-needed` reason for implementation PRs |
| H17 | Partial reads were undefined: whether the config version pre-read and the stale pre-read call `end()`, and which error each failure gives (H-A14, H-B3, H-C19, H-C24) | Low | Spec 017 R16 defines them; spec 011 R3, spec 013 R12 and §4 step 7 state the order and errors; vector `stale_trailing_garbage` |
| H18 | Nothing built keys or a `ChannelCtx` from a `Config` (H-A18, H-C20) | Low | `Config::channel_key()` (spec 011 R6) and `ChannelCtx::from_config` (spec 013 R19) |
| H19 | `seal` took the public key apart from the secret key, so a mismatched pair sealed blobs nobody accepts (H-B8) | Low | `SenderKey`, built only from a seed (spec 013 R5) |
| H20 | Small ones: a wrong citation of 015 R8, a T14 case below the smallest payload, an open question that belonged to 023, `presentation` untested, two fixed-size comparisons without `ct_eq`, an impossible final-bits vector, the `dead_code` allow, the missing verification-QR call in §9, the first generation of a file, the generator against AGENTS 15, test hooks nobody defined (H-A13, H-A15, H-A16, H-A19, H-A20, H-B6, H-C14, H-C18, H-C22, H-C23, H-C24) | Low | Corrected in the specs; AGENTS 15 names the generator's exception |

**Round 2**, the same three passes over the fixes (R2-A1–R2-A14, R2-B1–R2-B11, R2-C1–R2-C15). Changes applied before anything was committed:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H21 | The signature of one's own blob was dropped at `sent_at + ttl_ms + 360 000`, while a server can still get a replay accepted until twice that, so it could raise a false own-key alert at will (R2-A1, R2-B1) | High | Kept until `sent_at + 2·(ttl_ms + 360 000)`, independent of the purge; sealing fails rather than dropping one (ADR 0029, §4, spec 012 R15) |
| H22 | Exempting stale messages below the send counter from the alert let a thief date a message to look stale to the victim and fresh to a member with a slower clock (R2-B2, R2-A8, R2-B7) | Medium | Every message from one's own key the device did not seal raises the alert, stale or not, unless it is beyond the retention window (`OwnKey::Expired`); one's own key is never a peer; regeneration records the old key as retired (ADR 0029, §4, spec 012 R11) |
| H23 | Padding the config record reallocated a buffer holding `K_ch` without wiping it (R2-A5, R2-C1) | Medium | `seal_file_with_key` pads in a buffer of fixed capacity 1 024 (spec 011 R19) |
| H24 | The slice plans of 011 and 013 still placed tests before the code they need, and 013's last slice held the whole script section (R2-A2, R2-C3, R2-C8) | Medium | 013 in three slices; 011 R22 with its first vectors; spec 015 R13 says how a test grows across slices |
| H25 | Free-form dispatch needed source parsing and a lint-clean fallback that does not exist (R2-C5, R2-C6) | Medium | `vectors::check_all` with a table of entries; `kind()` and `has_expected()` (spec 015 R10, patterns §6) |
| H26 | The strict-check negative signatures could be junk that any verifier rejects, and the script ignored them (R2-B4, R2-B5) | Medium | Explicit constructions and the RFC 8032 equation checked by the script; the whole blob recomputed (spec 013 R18) |
| H27 | No field could hold the outcome of a positive receive vector (R2-A4, R2-C4) | Medium | Text field `content` (`specs/vectors/README.md`, spec 015 R3) |
| H28 | The fuzz entries could not reach the `text_k1` inputs under `cfg(fuzzing)`, and the `_outcome` twins were unneeded (R2-A6, R2-C10, R2-C11, R2-C12) | Medium | The inputs are declared once in `proto/envelope/text_k1.rs`; `fuzz_entry` returns its verdict; seed layout of `record_decode` (specs 013, 016) |
| H29 | Small ones: the new future-date example was not in whole minutes, a T13 case contradicted R11, the header byte comparison had no reader, stale wording, the Limits row, the step 7 exception, T04 of 012 scanning 013's files, `error.rs` dead code, CI step prefixes, the T10 nightly claim, the lifetime wording of ADR 0030, a pointer from ADR 0019 (R2-A3, R2-A7, R2-A9–R2-A14, R2-B3, R2-B6, R2-B9, R2-B11, R2-C2, R2-C7, R2-C9, R2-C13–R2-C15) | Low | Corrected; ADR 0019 gains a stale-reference pointer to ADR 0029 |

Not changed on purpose: a signed blob with no readable `sent_at` stays `Unreadable` and can be revived by a server (R2-B10); only a non-conforming signer produces one, and ADR 0030 records it.

**Round 3**, the same three passes over the round 2 changes (R3-A1–R3-A11, R3-B1–R3-B12, R3-C1–R3-C11). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H30 | The constructions of H26 could not be built: two of the `010.json` keys are not the points their names say, and the generator has no SHA-512 or scalar arithmetic; and the check bought nothing, since `010.json` already proves the strict verifier (R3-A1, R3-A2, R3-B1, R3-B3, R3-C1) | High | H26 undone: the strict-check negatives of 013 carry the `010.json` bytes as before and the script checks no equation; it still checks `aead_forged_signed` and `signed_ciphertext_only`, whose tagged range is now stated (spec 013 R18) |
| H31 | `fn` pointers in tuple slices trip `clippy::type_complexity`; `fuzz_entry` returning crate-internal types trips `private_interfaces` (R3-C2, R3-C3) | High | `Checker` and `Section` aliases (spec 015, patterns §6); a scoped `allow` and example signatures (spec 016) |
| H32 | Spec 013 and ADR 0027 still limited the stale own-key alert to `counter ≥` send counter (R3-A3, R3-B4) | Medium | Spec 013 follows ADR 0029; ADR 0027 gains a stale-reference pointer to ADR 0029 |
| H33 | A backward step of the device clock after dropping a signature raised a false alarm; the verdict ran after the commit, so a crash lost the alert (R3-B5, R3-B6, R3-B7) | Low | Signatures kept one more `ttl_ms + 360 000`; the verdict precedes the single commit; the signature moves with the `outbox` entry and is keyed on `sent_at` (§4, ADR 0029, spec 012) |
| H34 | Small ones: `spec` missing from the text fields, T16 not checking `Opened::sent_at`, R9 and T11 in the wrong slice, T13 of 015, T17 of 012 not in whole minutes, test-file placement in 012, stale names in 016 and AGENTS 21, `commits` in `010.json`, generator-only constants of `text_k1`, the seed table, two unlisted crate-internal parsers, the word-list digest wording, `seal_padded` length, one's own key in pre-verification, lifetime wording in 012 (R3-A4–R3-A11, R3-B8, R3-B9, R3-B12, R3-C4–R3-C11) | Low | Corrected |

Not changed on purpose, and left to their own specs: three `010.json` vectors whose names overstate what they test (`pk_identity` is the order-4 point, `pk_small_order` is not a point, `r_small_order` is a large-order R), which is a revision of the implemented spec 010 (R3-B2); leaving a channel without sending `key_retired`, which is spec 021's and 025's (R3-B11); the residual limit of the own-key alert under a colluding server or clocks off by more than one TTL, now written in ADR 0029 (R3-B10).

**Round 4**, a final confirmation in the same three passes, limited to Blocker, High and Medium (R4-A1–R4-A6, R4-B1, R4-C1–R4-C3). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H35 | The envelope signature travelled in the clear, so whoever held one member's `pk_u` — which the verification QR shows in plain text — could test it against every blob and learn which ones that member wrote, what ADR 0018 hides from the server (R4-B1) | Medium | The signature travels masked with bytes 40..104 of the header keystream (ADR 0032, §4, spec 012 R4 and R16, spec 013 R1, R4, R11, R18, R20) |
| H36 | Crate-internal types returned by `pub` fuzz entries are a hard type-privacy error in the fuzz crate, so no target could compile (R4-C1) | Blocker | `pub` entries return `()` and call crate-internal `_verdict` functions; the `allow` is gone (spec 016 R8) |
| H37 | Spec 017 was the first to write `cfg(fuzzing)` but the `check-cfg` entry came only with spec 016, so 017's first slice failed under `-D warnings` (R4-A1) | High | Spec 017 R17 carries the entry; spec 016 relies on it |
| H38 | Other buffers holding `K_ch` or the password could still grow and leave unwiped copies, and the padded buffer was not observable (R4-A3, R4-A4) | Medium | No secret buffer grows (spec 011 R19); `padded_record` is the seam T19 checks |
| H39 | Small ones: README and 015 R12 disagreed on what the script recomputes, T12 and T13 of 013 had no slice-(a) case, `Verified::signature` had no requirement, `QR_PREFIX` could not go through `ct_eq`, `words` could not be written infallibly under the lints (R4-A2, R4-A5, R4-A6, R4-C2, R4-C3) | Medium | Corrected (README, specs 013 and 014) |

**Round 5**, confirmation in the same three passes, limited to Blocker, High and Medium: none of the first two; 12 Medium, all wording of tests, vectors and interfaces (R5-A1–R5-A8, R5-B1, R5-B2, R5-C1, R5-C2). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H40 | The echo compared the unmasked signature, but the device would keep the masked bytes of its `outbox` blob, so every echo would raise a false alarm (R5-B2) | Medium | `seal` returns `Sealed { blob, signature }` with the unmasked signature, which the device keeps (§4, spec 012 Context, spec 013 R20) |
| H41 | The strict-check negatives did not say they are edited before masking, so a generator slip would make them vacuous (R5-A6, R5-B1) | Medium | Edited unmasked, then masked; their checkers verify the edit (spec 013) |
| H42 | Tests that could not pass or did not check their requirement: canonicalisation capacity, label and host limits, R6 split across slices, `header_sealed` without a `K_ch`, the keystream buffer, `Payload` without `Display`, the shape of the fuzz entries; `RecordError` leaving `proto` through a fuzz verdict (R5-A1–R5-A5, R5-A7, R5-A8, R5-C1, R5-C2) | Medium | Corrected (specs 011, 012, 013, 016) |

**Round 6**, the same three passes (R6-A1–R6-A4, R6-B1, R6-B2, R6-C1–R6-C5); the two findings of pass B concern the regeneration flow of phase 2 and were decided with the human reviewer. Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H43 | A thief writing with rising counters could get a blob in before the victim's `key_retired`, which every receiver then discarded as `Replay` before reading its type; the old key was already erased, so the retirement failed for good and silently (R6-B1) | High | Every `key_retired` is sealed with `counter = 2^64 − 1` and counts for no gap (ADR 0033, §4, spec 012 R17) |
| H44 | An `outbox` entry published after its TTL was stale everywhere while the server still acknowledged it, so a `key_retired` written offline never retired the key (R6-B2) | Medium | No stale entry leaves; an ordinary one is reported as not delivered, a pending `key_retired` is sealed again with the old key kept until its `ack` (ADR 0034, §4, §7) |
| H45 | Test and interface gaps: strict-check vectors whose checkers needed `010.json`, `RecordError` reaching `fuzz_entry` untested, the policy byte and short inputs untested, patterns §5 without the kept signature, a missing `Secret::copy_from`, private `ChannelKeys` fields read by a sibling module, the margin constant defined after its first user, source-scan tests with no file list, the fuzz manifest's path dependency (R6-A1–R6-A4, R6-C1–R6-C5) | Medium | Corrected (specs 011–013 and 015–017, patterns §4 and §5); ADR 0016 and 0027 gain pointers to ADR 0033 and 0034 |

**Round 7**, the same three passes (R7-A1–R7-A6, R7-B1, R7-B2, R7-C1–R7-C3). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H46 | The hand-out test used the sender's clock alone, so with a server clock ahead or a slow publish an entry left just in time, arrived stale and was acknowledged, and a retirement could still be lost (R7-B1) | Medium | A pending `key_retired` is re-sealed at every hand-out, and an `ack` past the bound by its `received_at` is a message not delivered; `Channel::outbox(&mut self, now)` returns what was not delivered (ADR 0034, §4, §7, §9) |
| H47 | A retirement expires on the server like any message, so members who do not connect within the TTL never receive it; nothing said so, and ADR 0033 overstated what the victim sees (R7-B2, R7-A5) | Medium | Documented in ADR 0034 and the §7 regeneration warning; ADR 0033's consequence corrected |
| H48 | `decode_test_record` returned `core::Error` from spec 017, which lands before the error type exists; the `SOURCES` check used a git pathspec that skips top-level files, landed after the tests that use it and named later specs; `ChannelKeys` fields were not readable by the generator; 013 R15 still owned the margin; T19 of 011 contradicted `create` (R7-A1–R7-A4, R7-C1–R7-C3) | High | `decode_test_record` belongs to spec 016; `SOURCES` lives in `lib.rs`, lands in 015 slice (a), is checked with `crates/core/src/*.rs` and by a mechanical T15; fields `pub(crate)`; wording fixed (specs 011–013, 015–017) |

**Round 8**, the same three passes; pass B found every spec 011–017 ready (R8-A1–R8-A3, R8-B1, R8-B2, R8-C1–R8-C4). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H49 | A re-sealed retirement kept its `ClientRef`, so a late `ack` of an old copy was judged against the new copy's `sent_at` and could erase the old key with the retirement lost; every re-seal stored a signature nobody would read, and a lying server could fill the store (R8-B1, R8-B2) | Medium | A fresh `ClientRef` per copy, each `ack` judged against its own copy, at most one re-seal per minute, no signatures kept under a retired key (ADR 0034, §4) |
| H50 | T13 of 015 could not reach the other specs' checker tables; T15 of 015 forbade what 016's tests need to read the fuzz targets; `all` was out of reach for the generator; unused accessors failed `dead_code`; 015 R12 and 013/014 disagreed on what the script checks (R8-A1–R8-A3, R8-C1–R8-C4) | High | T13 counts `check_all` calls in `SOURCES`; `FUZZ_TARGETS` in `lib.rs` (spec 016); the generator may read `all`; `dead_code` allow on `mod vectors`; verdicts left to the Rust tests and the words added to 014 R8 |

**Round 9**, the same three passes (R9-A1–R9-A3, R9-B1–R9-B3, R9-C1–R9-C3). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H51 | A late `ack` re-sealed at once, so a server acking late looped without limit, and the older copies to remember were unbounded; the `ack` check looked only backward, so a sender clock ahead or a server clock behind by more than the margin passed; spec 012, §4 and ADR 0029 still kept signatures under a retired key (R9-B1–R9-B3, R9-A2) | Medium | Only the current copy is remembered, a late `ack` only marks it not delivered, re-sealing waits for a hand-out in a later minute, the `ack` is checked on both sides, and signatures under a retired key are dropped (ADR 0029, 0034, §4, §7, spec 012) |
| H52 | T13 of 015 could never match rustfmt's layout of `check_all`; the fuzz manifest had no licence, so `cargo deny` failed; `unknown_key_ignored` could not be re-encoded by the script; the "only code that builds a file" and "only callers of `message_key`" clauses ignored tests and the generator (R9-C1–R9-C3, R9-A1, R9-A3) | High | T13 strips whitespace; `license = "MIT"` and `publish = false` in the fuzz manifest; the vector excluded by name; both clauses limited to non-test code (specs 011, 013, 015–017) |

**Round 10**, the same three passes; pass B found every spec 011–017 ready (R10-A1, R10-B1, R10-C1–R10-C5). One decision was taken with the human reviewer (H53). Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H53 | `cargo deny` over the fuzz crate failed: `libfuzzer-sys` builds with `cc`'s `parallel` feature, whose `jobserver` depends on the banned `getrandom`; the path dependency had no version under `wildcards = "deny"`; cargo-deny accepts no `reason` key in licence exceptions (R10-C1) | High | The human reviewer allowed `jobserver` as a `getrandom` wrapper, a build-time dependency of the fuzz crate only, which never ships; spec 016 R12 names that `deny.toml` line, the versioned path dependency and comments in place of `reason` |
| H54 | §4 read as removing a stale pending `key_retired` instead of sealing it again (R10-B1) | Medium | §4 separates ordinary entries from a pending `key_retired`, which is never removed and is re-sealed before the stale check |
| H55 | Mechanisms that bought nothing: the header byte compared with key 0 (the byte is unauthenticated and already checked), the keystream in a `Zeroizing` buffer (it reveals only public-after-open bytes), and `FUZZ_TARGETS`, a hand-kept second reader of the targets that could not see an eighth one (R10-C3–R10-C5) | Medium | All three removed (§5, specs 011, 012, 015, 016); the target checks live in `scripts/check_fuzz_targets.sh` |
| H56 | Spec 012 had no slice plan; the host limit of 253 bytes could never be reached under a `server_url` of at most 256 bytes, so T05 could not pass (R10-C2, R10-A1) | Medium | Two slices for 012; the host bounded by the URL alone (spec 011 R5, T05) |

**Round 11**, the same three passes: pass B found nothing. Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H57 | The slice plan of 016 left behind by H55; R7 read two ways on `pub(crate)`, with exclusions that could never match; the fuzz deny step lacked `-D checksum-mismatch`, so a changed libsodium build script could reach the nightly runner unread (R11-A1, R11-C1, R11-C2) | Medium | The script lands in slice (a); R7 counts `pub` only; the fuzz step carries `-D checksum-mismatch` (spec 016) |
| H58 | `libsodium-sys-stable` also brings the decompressor `libflate` (and `libflate_lz77`) through its build script, with no `[bans]` entry naming its wrapper as AGENTS 24 requires (R11-C3) | Medium | Both added to `[bans]` with their exact wrappers, and named in the comment (`deny.toml`); `cargo deny` and the tests stay green |

**Round 12**, the same three passes: pass B found nothing for the second time. Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H59 | `zlib-rs` and `zopfli` reach the graph through the libsodium build script with no `[bans]` entry naming their wrapper, the gap H58 closed for `libflate` (R12-A1) | Medium | Both added with their wrappers; `miniz_oxide`, `lzma-rs`, `xz2`, `bzip2` and `snap` banned outright (`deny.toml`); `cargo deny` and the tests stay green |
| H60 | After H57 two crate-internal file parsers of spec 011 were reached by no target and named nowhere, against AGENTS 21; committing the fuzz `Cargo.lock` put slice (a) over 400 lines and broke the libsodium bump procedure (R12-A2, R12-C1–R12-C3) | Medium | The exclusion list names both with their reasons, so AGENTS 21 stands as written; the fuzz lockfile is not committed, since `-D checksum-mismatch` already stops an unread build script (spec 016) |

**Round 13**, the same three passes: the specs and ADRs came through clean for pass B for the third time. Changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| H61 | `deny.toml` is a denylist, and crates already in the lock (`rand_chacha`, `rand_xorshift`, `fastrand`, `minisign-verify`) had no entry naming their wrapper, while common drop-in cryptographic and compression crates were not banned at all (R13-B1–R13-B3) | Medium | Wrappers named for the four; 17 cryptographic and 15 compression crates banned outright; `cargo deny` and the tests stay green. The review of every new dependency (AGENTS 8) remains the real barrier, since no denylist is complete |
| H62 | Without a fuzz lockfile, the fuzz deny step resolved `libsodium-sys-stable` afresh and would go red on any upstream build-script change, and nothing kept the fuzz outputs out of git (R13-A1) | Medium | The CI copies the workspace `Cargo.lock` into the fuzz crate before its steps; `crates/core/fuzz/.gitignore` (spec 016 R12) |
| H63 | Three slices (011 b, 013 b, 017 a) are likely above 400 lines, so the slice count and AGENTS 14 could not both hold (R13-C1) | Medium | Spec 015 R13: slices fix the order, not the number of pull requests; an oversized slice is split into consecutive ones |

**Round 14**, the same three passes: pass B clean for the fourth time; pass C found one Medium, T12 of spec 016 checking CI files that land only in slice (b) (R14-C1), moved to T10.

## Audit G

**2026-09-24 — Audit G, coherence review of the whole documentation after audit F (spec, threat model, ADRs, audit log, `AGENTS.md`, skills, feature specs, templates), looking for duplication, contradictions and stale metadata.** No decision changes; the ADR edits are stale-reference corrections under the rule added to `docs/adr/README.md`. Substantive changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| G1 | Spec 001 R8 named specs 011–013 as the paths `adr-guard` protects, while the CI and §10 protect 011–014 and 017 since E21 | Medium | R8 brought in line with the CI (spec 001) |
| G2 | "A rejection commits nothing but the cursor" (AGENTS 23, §10) and "asserts `commits == 0`" (skills, PR template) read as a contradiction; only `specs/vectors/README.md` said the cursor is not counted | Medium | Defined once: `commits` counts the commits other than the cursor's (AGENTS 23, §10 DoD, PR template, `specs/TEMPLATE.md`, skills) |
| G3 | Spec 010 still placed the vector loader in `crypto/`, sent the `CryptoError` mapping to spec 027 (spec 011 R20 owns it) and named a `decrypt` fuzz target that does not exist | Low | Corrected (spec 010) |
| G4 | Spec 016 R11 demanded eight round-trips that the owning specs already carry and its own Out of scope excluded; `Config::open_encrypted` matched R7 but was neither targeted nor excluded; the record fuzz schema was `cfg(test)` in 017 and "fuzz-only" in 016 | Medium | R11 dropped and R12–R13 renumbered; `open_encrypted` in the exclusion list; one test schema under `cfg(any(test, fuzzing))` (specs 016, 017) |
| G5 | `patterns.md` gave `Session::new(host)` while §9 takes `server_url` | Low | Aligned with §9 |
| G6 | Audit E numbered its internal passes A1…, B1…, C1…, colliding with the top-level ids of audits A–C; ADRs 0023–0026 cited them as if they were | Medium | `E-` prefix on every internal id, in the log and in the four ADRs |
| G7 | Stale metadata: spec header "post-audit E", §13 without F, §11 tree ending at ADR 0026, ADR README "four audits", ADR 0012 naming `ciborium` and ADR 0015 as current, a pending-review item about `ciborium`, §12 citing ADR 0025 as "closed without an ADR", `DEFAULT_SERVER_URL` open decision cited by spec 000 but absent from §12 | Low | All brought up to date (§1 pointer, §11, §12, §13, ADR README and 0012, audit log) |
| G8 | Three copies of "what it does not promise": §1, the threat model (with three bullets §1 lacked) and the README | Low | §1 is the single list, with the three bullets; `docs/threat-model.md` keeps the lint-checked table and points to §1; README labels its copy as plain words |
| G9 | The three client skills shared about 60% of their text with platform nouns swapped; the rust skill and `patterns.md` copied AGENTS 4, 5, 12, 18, 22, 23 and the style guide | Medium | `architecture` §7 "Client shape" owns the shared part; client skills keep platform mechanics; rust skill and patterns cite AGENTS by number |
| G10 | The architecture skill said `store` must not read a clock; AGENTS 10 binds `core` only and `clippy.toml` allows the I/O crates one audited place | Low | Skill aligned with AGENTS 10 |
| G11 | `specs/TEMPLATE.md` showed a vector schema without `kind`, `source`, `origin`, and required dependencies to be `implemented` while every phase 1 spec depends on `accepted` ones | Low | Template corrected |

Not changed on purpose: the §2 table copy in `docs/threat-model.md` and the two ADR tables (`docs/adr/README.md`, §3), because the doc lint keeps them equal and collapsing them would touch specs 002 and 003 and the lint itself; the closed "Open questions" of specs 011–017, which record the reason of each decision.

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
