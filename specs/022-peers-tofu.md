# 022 — Peers: trust on first use, labels, verification and name collisions

Status: accepted
Phase: 2
Related ADRs: 0006, 0007, 0019, 0029, 0043
Depends on: 010-primitives-wrapper, 014-fingerprint, 021-channel-session
Blocks: 023-ttl-purge, 024-key-retired, 026-peer-limits, 027-core-api, 055-verify-ui, 054-qr-invite
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-28

## Context

There is no member list (ADR 0006): a key becomes a peer the first time one of its messages is consumed, and the user decides what it is — a name, verified, muted. `docs/spec.md` §7 gives the states (unknown, labelled, verified, muted, retired), the presentation rules and the collision rules that make impersonation visible. This spec implements the peer record of spec 020-store-files, the calls that change it, the verification by QR and by words, and the name comparison of §7 over the Unicode data of the standard library (ADR 0043).

Retirement, received or manual, is spec 024-key-retired; the counts, the room check and eviction are spec 026-peer-limits, which plugs into R7–R9 here (until it is implemented, every call finds room). Every rule that decides trust is in `core`, so the clients only paint what `peers()` returns (architecture skill §7: "views decide presentation, never trust").

**In plain words.** The first time someone new writes, the channel writes down their key and the name they suggest, in grey: nobody vouches for it. You can give them your own name for them, and a name you have given one person cannot go to another unless you verify the new one — scanning their code or comparing twelve words. Names are compared ignoring capitals, spaces and invisible characters, so "ALICE", "Al ice" or "Alice" with a hidden character is still "Alice". A name written with look-alike letters, such as a Cyrillic "А", is a different name: it still shows in grey with its own four words, and only verification proves who someone is. When a new key arrives claiming a name you already trust, or your own name, or two keys share the same four words, the channel says so.

## Requirements

**The record**

- R1 A consumed, not stale message other than a `key_retired` from a `pk` with no peer record, other than one's own `pk_u` (never a peer), MUST create one with no label, `verified` and `muted` false, no `retired_at`, `first_seen = last_seen = now`, `max_counter` set by spec 021-channel-session R11, and `last_display_name` set to the message's name when it has one, in the commit of that message.
- R2 Each later consumed, not stale message of that peer MUST set `last_seen = now`, and `last_display_name` to its name when it carries one, in the same commit; a name whose key (R4) is empty replaces the previous one too, and is handed out as no name (R6).
- R3 `peers()` MUST return every peer record, in `first_seen` order with ties in creation order, as a `Peer` with the fields of the Interface, and MUST NOT commit.

**Names**

- R4 `name_key(text)` MUST be the text with every character removed that is `White_Space` (`char::is_whitespace`) or in the table `INVISIBLE` of R5, then the Unicode lowercase mapping (`str::to_lowercase`), with every U+03C2 GREEK SMALL LETTER FINAL SIGMA then replaced by U+03C3, since `to_lowercase` picks the final form from the letters around it and the removed white space changes them; no normalisation, confusable skeleton or other fold (ADR 0043). Two names collide exactly when their keys are equal and non-empty.
- R5 `INVISIBLE` MUST be a table of code point ranges written by hand in `core`, the union of General_Category Cf and `Default_Ignorable_Code_Point` of the Unicode version of the pinned toolchain (`char::UNICODE_VERSION`), the blank-rendering code points listed with their reason in the table's doc comment (at least U+2800 BRAILLE PATTERN BLANK, U+3164 HANGUL FILLER and U+FFA0 HALFWIDTH HANGUL FILLER), and the line and paragraph separators U+2028 and U+2029, which could draw a second line that looks like another sender, with that version and the source files (`UnicodeData.txt`, `DerivedCoreProperties.txt`) named in its doc comment; a test pins the number of ranges and that `char::UNICODE_VERSION` is the version the doc comment names, so that a change of the table or of the toolchain's Unicode data is a reviewed diff.
- R6 Every name the core hands to a client — `label` and `suggested_name` of a `Peer`, `display_name` of a `Received` or a `Message`, `suggested_name`, `local_name` and `own_display_name` of a `ChannelInfo` — MUST have its Cc characters and the characters of `INVISIBLE` removed by `clean_name`, so that no client renders them (`docs/spec.md` §7); an optional name whose `name_key` is empty (only white space or invisible characters) is handed out as `None`, and a required one (`suggested_name` of a `ChannelInfo`) as the empty string; `channel_name` of a `BrokenChannel` (spec 027-core-api) is cleaned the same way and is `None` when empty; which the client replaces by its own placeholder.

**Calls**

- R7 `label(peer, name, now)` MUST return, in this order: `Error::UnknownPeer` for a `PeerId` with no record; `Error::BadPayload` for a name that is empty, longer than `MAX_NAME` of spec 020-store-files (64 bytes), contains a Cc character or whose key (R4) is empty; `Error::LabelInUse` when the name collides with the label of another peer that is not retired, unless the target peer is verified; the admission check of spec 026-peer-limits for an unknown peer; and otherwise commit the label.
- R8 `verify(peer, label, now)` MUST return `Error::UnknownPeer` for no record; for a peer with a label, commit `verified = true`, keeping that label and ignoring the given one; for a peer with none, return `Error::BadPayload` when `label` is `None` (a verified peer always has a label, as in §7), and otherwise apply the label rules of R7 with the target counted as verified and the admission check of spec 026-peer-limits, any failure failing the whole call with nothing committed, and commit the label and `verified = true` together, so that the 12-word check can give a new key a label an unverified old key still holds (`docs/spec.md` §7); a verified peer that is also retired stays retired.
- R9 `verify_scanned(qr, label, now)` MUST parse the QR with `parse_verify_qr` of spec 014-fingerprint for this channel (its `BadPayload` and `WrongChannel` returned as they are), return `Error::OwnKey` for one's own `pk_u` or one of `own_old_keys`, and then: for a `pk` with a record, `verified = true` and, when it has no label, the given label; for a `pk` with none, a new record, verified, with the given label, no `max_counter` and `first_seen = last_seen = now` (pre-verification, `docs/spec.md` §7). The label rules of R7 apply, with the target counted as verified, only when the label is written (a peer that already has a label keeps it and the given one is not checked), and any failure of them, or of the admission check of spec 026-peer-limits, MUST fail the whole call with nothing committed.
- R10 `mute(peer, muted)` MUST return `Error::UnknownPeer` for no record and otherwise commit `muted`; with the same value it MUST NOT commit.
- R11 Every call of R7–R10 that returns an error MUST commit nothing, and each MUST have a `FailingStore` test that fails its commit and checks the reopened state.
- R12 `fingerprint(pk)` MUST return `presentation` of spec 014-fingerprint for any `pk`, with or without a peer record — a retired peer, one of `own_old_keys`, or the sender of a retained message whose record was evicted or forgotten — since it is a pure function of the channel and the key; `own_fingerprint()` the same for one's own `pk_u`.

**Warnings**

- R13 For an unknown peer, `Peer::claims_name_of` MUST be the `PeerId` of a labelled, verified or retired peer whose label collides with this peer's `suggested_name` (a retired label counts, since an impostor appears when a key is retired), the one first seen when several do (ties in creation order), and `Peer::claims_own_name` MUST be true when its `suggested_name` collides with `own_display_name`, which is how two devices of one person see each other (`docs/spec.md` §7).
- R14 `Peer::label_collides` MUST be true when this peer's label collides with another peer's label, retired peers included as in R13, which R7–R9 allow only for a verified target or next to a retired label; a client shows the short identifier next to both.
- R15 `Peer::short_collides` MUST be true when the 4 words of this peer equal those of another peer or of one's own `pk_u`; a client then shows the 12 words of both with the warning of §7.

**Dependencies and property test**

- R16 `name_key`, `clean_name` and `INVISIBLE` MUST use the standard library only: `core` gains no dependency for names, and specs 010-primitives-wrapper and 016-fuzz-harness are not amended (ADR 0043). `name_key` reads a `&str` that the payload decoder, fuzzed by spec 016-fuzz-harness, has already produced, so it has no fuzz target of its own (AGENTS 21); a property test MUST show that `name_key` and `clean_name` never panic and that collision is symmetric.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `label` | 1..=`MAX_NAME` (64) B UTF-8, no Cc, a non-empty `name_key` | `BadPayload` |
| `PeerId` | a `pk` with a record | `UnknownPeer` |
| Verification QR | spec 014-fingerprint | `BadPayload`, `WrongChannel` |
| Name given to `name_key` | 0..=64 B | the callers bound it; the property test of R16 reaches 256 B |

## Interface

```
crates/core/src/session/channel/peers.rs          the peer list and calls, R3, R7–R15 (R1, R2 in channel/receive.rs)
crates/core/src/session/names.rs                  name_key, names_collide, clean_name, shown_name and the table INVISIBLE (R4–R6)
crates/core/src/session/channel/tests/peers.rs    s022_* tests of the record, the calls and the warnings
crates/core/src/session/names/tests.rs            s022_* tests of the names
```

```rust
pub struct Peer {
    pub id: PeerId,
    pub label: Option<String>, pub suggested_name: Option<String>,
    pub verified: bool, pub muted: bool, pub retired_at: Option<u64>,
    pub first_seen: u64, pub last_seen: u64,
    pub short: Vec<String>,                 // the 4 words of spec 014
    pub claims_name_of: Option<PeerId>, pub claims_own_name: bool,
    pub label_collides: bool, pub short_collides: bool,
}

impl Channel {   // pub(crate); spec 027-core-api exposes them through Device
    pub(crate) fn peers(&self) -> Result<Vec<Peer>, Error>;   // Internal only if a fingerprint cannot be computed
    pub(crate) fn label(&mut self, peer: PeerId, name: &str, now: u64) -> Result<(), Error>;
    pub(crate) fn verify(&mut self, peer: PeerId, label: Option<&str>, now: u64) -> Result<(), Error>;
    pub(crate) fn verify_scanned(&mut self, qr: &[u8], label: &str, now: u64) -> Result<PeerId, Error>;
    pub(crate) fn mute(&mut self, peer: PeerId, muted: bool) -> Result<(), Error>;
    pub(crate) fn fingerprint(&self, peer: PeerId) -> Result<Fingerprint, Error>;
    pub(crate) fn own_fingerprint(&self) -> Result<Fingerprint, Error>;
}
pub(crate) fn name_key(text: &str) -> String;
pub(crate) fn names_collide(first: &str, second: &str) -> bool;   // equal, non-empty keys (R4)
pub(crate) fn clean_name(text: &str) -> String;
pub(crate) fn shown_name(text: &str) -> Option<String>;            // an optional name as R6 hands it out
pub(crate) const INVISIBLE: &[(u32, u32)];
```

`core::Error` gains `UnknownPeer`, `LabelInUse` and `OwnKey`. `label` takes `now` because it shares the admission path of spec 026-peer-limits with `verify_scanned`. `verify_scanned` is the call spec 014-fingerprint left open, defined here and exposed by spec 027-core-api; it returns the `PeerId` it verified.

**PR slices** (AGENTS 14): (a) `name_key`, `INVISIBLE` and `clean_name` (R4, R5, R16, and R6 tested on `clean_name` directly); (b) the record and the calls (R1–R3, R7–R12, and T06's `peers()` and `Received` half); (c) the warnings (R13–R15). Each test clause lands in the slice that implements the last behaviour it needs; the list above names where each requirement is implemented, and a test that spans slices is completed clause by clause.

## Security

- The key catches case, white space and the invisible characters and blanks of R5, the differences a user makes without meaning to or an impostor makes with no effort. Look-alikes — letters of another script ("Аlice" with a Cyrillic А), a capital I for an l, digits for letters, full-width forms, combining marks — do not collide, a stated residual (ADR 0043): such a key still shows as an unknown, grey, quoted, with the unknown mark and its own short identifier, and verification, not the name, is what authenticates (§7). A prefilled field cannot lead the user to give it the label of the person it imitates, since spec 055-verify-ui R15 never fills the label from a suggested name.
- Trust on first use is the model (ADR 0006): an intruder with the config who writes appears as an unknown, grey, with a mark. What stops him from becoming "Alice" is R7: the label Alice already has cannot go to his key unless the user verifies it.
- The Unicode data is the pinned toolchain's (`char::UNICODE_VERSION`) and the table of R5; two clients built with different toolchains can disagree only on a rare collision, which changes a warning or a refusal, never a byte on the wire. Every platform runs the same Rust code, so no vector file is needed.
- The short identifier identifies and never authenticates (spec 014-fingerprint): R15 reports a collision and never resolves it.
- Pre-verification (R9) is the remedy to "this is my new phone": the member scans the new key in person before its first message, and may give it the label the old device holds.
- `claims_name_of` follows the suggested name of the peer's last message that carried one (R2): an unknown key that wrote as "Alice" and then sends a blank name or another one withdraws the warning, while its earlier message still reads "Alice". A stated residual (audit AE): the unknown mark, the grey name and the short identifier, which the sender cannot remove, stay on every one of its messages, and verification is what authenticates.
- Names are content: they never reach a log, an error or a `Debug` (AGENTS 19); the `Debug` of `Peer` and `Sender` shows the 4-byte prefix of a key and no name.

## Public API changes

None directly: spec 027-core-api exposes `peers`, `label` (with `now`), `verify`, `verify_scanned`, `mute`, `fingerprint` and `own_fingerprint` through `Device`, with the `Peer` record and three `Error` variants.

## Test cases

- T01 (covers R1): `s022_t01_r01_first_message_creates_peer`: a new `pk` → one record with the suggested name; a stale message or a `key_retired` → none; a fresh blob from one's own `pk_u` sealed elsewhere → no peer record (the own-key rule of spec 021-channel-session R14 applies instead).
- T02 (covers R2): `s022_t02_r02_later_messages_update`: `last_seen` moves; a message without a name keeps the previous one.
- T03 (covers R3): `s022_t03_r03_peers_in_order`: three peers in `first_seen` order; `commits = 0`.
- T04 (covers R4): `s022_t04_r04_name_key_collisions`: each pair collides — "Alice"/"ALICE", "Mike"/"MIKE", "Olivia"/"OLIVIA", "Al ice"/"Alice", "Alice"/"Ali\u{3000}ce", "Alice"/"Alice\u{2800}", "Alice"/"Ali\u{200B}ce", "Alice"/"Ali\u{034F}ce", "Alice"/"Ali\u{3164}ce", "Alice"/"Ali\u{FFA0}ce", "Élodie"/"ÉLODIE", "Νίκος Π"/"ΝΊΚΟΣ Π", "οδος α"/"ΟΔΟΣ Α", "Νίκοσ"/"Νίκος"; these do not, the residual of ADR 0043 pinned so that it is neither closed nor widened by accident — "Alice"/"Alicia", "Alice"/"Аlice" (U+0410), "Alice"/"AIice" (capital I), "Bob"/"B0b", "Alice"/"\u{FF21}lice" (full-width A), "Alice"/"Ali\u{307}ce"; "   " and "\u{200B}" have an empty key.
- T05 (covers R5): `s022_t05_r05_invisible_table`: U+200B, U+200D, U+202E, U+FEFF, U+034F, U+115F, U+1160, U+3164, U+FFA0, U+2800, U+2028 and U+2029 are in it; "a" and U+0020 are not; the range count matches the pinned value and `char::UNICODE_VERSION` is the version the doc comment names.
- T06 (covers R6): `s022_t06_r06_names_are_cleaned`: a suggested name with U+202E comes out without it, in `peers()` and in the `Received` (a name with a Cc character is dropped on decode by spec 013 R9, and `clean_name` is tested on U+0007 directly) (spec 023-ttl-purge T03 checks `messages()`); a `display_name` made only of `INVISIBLE` characters → `None`; a `display_name` of three spaces, or of U+3000 alone → `None`; "Bob\u{2029}Alice" and "Bob\u{2028}Alice" → "BobAlice".
- T07 (covers R7): `s022_t07_r07_label_rules`: each error of R7 in order; a label held by a retired peer (planted with the `testing` builders) is free; held by an unverified peer it is `LabelInUse` for an unverified target and allowed for a verified one; `commits = 0` on every error.
- T08 (covers R8): `s022_t08_r08_verify`: an unknown `PeerId` → `UnknownPeer`, `commits = 0`; an unlabelled peer with no label given → `BadPayload`, `commits = 0`; a labelled peer → verified, label kept, the given one ignored; an unknown given "Alice" while an unverified old key holds "Alice" → verified with that label, both flagged by R14; an invalid given label → `BadPayload`, `commits = 0`.
- T09 (covers R9): `s022_t09_r09_verify_scanned`: another channel's QR → `WrongChannel`; one's own → `OwnKey`; a known `pk` → verified; a new `pk` → a verified peer with the label and no `max_counter`, whose first message is then accepted from counter 0; a new `pk` labelled "Bob" while an unverified peer holds "Bob" → accepted (the flags are T14's); a label with a Cc character → `BadPayload` and no peer created.
- T10 (covers R10): `s022_t10_r10_mute`: mute and unmute commit; the same value twice commits once; `label`, `verify` and `mute` each set the peers-changed flag of spec 021-channel-session R1, which `take_peers_changed()` clears.
- T11 (covers R11): `s022_t11_r11_errors_and_failing_store`: every error case of T07–T10 → `commits = 0`; `label`, `verify`, `verify_scanned` and `mute` under a `FailingStore` → the reopened state is the one before.
- T12 (covers R12): `s022_t12_r12_fingerprints`: `fingerprint` equals `presentation` of the `pk` for a peer, a retired peer and an old own key (planted with the `testing` builders) and a `pk` with no record; `own_fingerprint` of `pk_u`.
- T13 (covers R13): `s022_t13_r13_claims`: an unknown suggesting "alice" next to a labelled "Alice" → `claims_name_of` names her; next to a retired "Alice" (planted with the `testing` builders) → names the retired peer; with two colliding labels → the peer first seen; an unknown suggesting one's own `own_display_name` → `claims_own_name`.
- T14 (covers R14): `s022_t14_r14_label_collision_flag`: two peers with colliding labels (the second verified, or pre-verified by `verify_scanned`) → both flagged; an unverified "Alice" next to a retired "Alice" → both flagged.
- T15 (covers R15): `s022_t15_r15_short_identifier_collision`: two keys whose fingerprints share their first 44 bits under a fixed test `channel_id`, and an identity seed with a key whose words collide with its `pk_u`, found once by a search outside the test suite and written as hex literals with a comment naming it, planted with the `testing` builders → both flagged; the key colliding with one's own → flagged.
- T16 (covers R16): `s022_t16_r16_name_key_property`: the property of R16 holds for arbitrary strings of up to 256 bytes; `s010_t25` still accepts exactly its two dependencies.

## Vectors

None: the comparison is local, it decides no byte on the wire, and all three platforms run the same Rust function, so the collision table of T04 is a unit test.

## Acceptance criterion

`cargo test -p privatechat-core s022_` green; clippy, `cargo deny` and the documentation lint green. Non-automatable: a second person checks `INVISIBLE` against `UnicodeData.txt` and `DerivedCoreProperties.txt` of the version it names.

## Out of scope

- Retirement, received or manual (spec 024-key-retired); limits, admission and eviction (spec 026-peer-limits).
- The dialog that retires the old key to free its label: the UI calls `retire` of spec 024 and then `label`.
- How each client draws grey names, icons and marks (spec 055-verify-ui R1–R8).

## Open questions

None.

Decided with the human reviewer on 2026-09-25 (recommendations accepted, `docs/audit-log.md`, Audit J decisions): 022-R7: a label cannot be removed once given (an unknown with a label is no longer unknown).; the recommendation taken: no "remove label" call in v1; the user can rename, verify, mute, retire or forget.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): skeleton before and after lowercasing, a hand-written table of invisible characters in place of a generated one, no vector file, pre-verification counted as verified and all-or-nothing, the own-name claim, `FailingStore` tests, the 010 and 016 amendments, PR slices
- 2026-09-25 revised after audit J round 2 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 3 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 11 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 12 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 13 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 14 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 23 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 24 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 25 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 26 (`docs/audit-log.md`)
- 2026-09-25 open questions decided with the human reviewer, recommendations accepted (`docs/audit-log.md`)
- 2026-09-28 revised after audit P (`docs/audit-log.md`): drawing points to spec 055
- 2026-09-28 accepted (Marc Vilardebó)
- 2026-10-04 amended by ADR 0043 (`docs/audit-log.md`, audit AB): `name_key` is lowercase with white space and `INVISIBLE` removed, with no Unicode crate, skeleton or fold; look-alikes a stated residual; no fuzz target and no amendment of specs 010 and 016; `INVISIBLE` pinned to the toolchain's Unicode version
- 2026-10-05 revised after audit AE (`docs/audit-log.md`): the final sigma folded in R4 (ADR 0043 amended), ties in creation order in R3 and R13, a blank name in R2, the withdrawn claim a stated residual, the Interface paths and helpers
