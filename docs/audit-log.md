# Audit log

Findings and applied changes of every audit of the specification, newest first; `docs/spec.md` §13 points here and every PR that changes §3–§6 adds a row.

## Audit AM

**2026-10-09 — Audit AM, the code audit of slice (c1a) of spec 028-session-sans-io (branch `028-traffic`): the `push` routed to `decrypt`, the `LogFull` stall, the stop after one's own key is used elsewhere and the freeze after a push's store error (R10's first half), with `after_send`; round 1 of three passes (A: conformance; B: the adversary, a key thief and a server; C: quality, tests and hand mutants).** No High finding and no production defect beyond AM1. Pass C ran 31 mutants: 24 killed, 1 equivalent, 6 survived, each killed below or removed with the code it mutated.

Decisions taken without the human, by the advisor (three passes): a `LogFull` stall begun with the own-key flag set stops, whether the `decrypt` that began it set the flag or it was set before (unanimous; spec 021 R19 has `check_own_key` return `true` whatever the flag, and audit J69 put the stop there for a thief's blob); the `ok` of a frozen channel still records its truncation, which sets memory alone (two to one; the minority would skip it so that a frozen channel calls nothing, and raises no privacy or security risk: the next connection finds the same truncation).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AM1 | A thief's blob beginning a `LogFull` stall on a channel whose own-key flag was already set did not stop the current key's entries, which the same blob one push later did (A, B) | Medium | The stop reads the flag after that `decrypt` alone; R10 and T10 amended; a test |
| AM2 | The test of the stop by `check_own_key` passed with no stop: the thief's counter removed the only entry it watched; `after_send`'s publish, its `Subscribed` check and its freeze check untested (A, C) | Medium | The test watches an entry above the thief's counter; a test of `after_send` subscribed, awaiting `ok`, disconnected and frozen, with no commit |
| AM3 | R10 says nothing of a frozen channel is called, while the `ok` records its truncation (A) | Low | R10 names the truncation record as the exception (decision above); T10 and a test with no commit |
| AM4 | T03's push clause rebuilt the seed's blob instead of reading the vector (A) | Low | Blob and `received_at` read from `013.json`, as `fuzz_seeds.py` does |
| AM5 | The tick `Reconnect` of a relieved stall repeated each tick until `on_disconnect` (B) | Low | Asked once a stall; a T10 clause |
| AM6 | Regeneration told by comparing the last old key with `!=` (AGENTS 22) and a cloned list; a mutant to `.first()` survived (B, C) | Low | `Channel::identity_epoch`, which every regeneration raises |
| AM7 | The net diff is over AGENTS 14's 400 lines (C) | Low | Justified in the pull request: about 230 of production code, the rest the tests of R10 |
| AM8 | `on_push` packs three arguments in a tuple where its callees take them apart; `check_room` uses `super::find` (C) | Far-fetched | None: a preference |

**Round 2.** Fresh passes on the whole change. AM1–AM6 hold. Pass C ran 43 mutants: 38 killed, 5 survived, each killed below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AM9 | A stall stopped after its tick asked for a new connection was written anew with `asked` false, so the next tick asked again (B, C) | Low | The stop changes the stall's `stop` alone; a test |
| AM10 | No test reached the `ok` of a stall without the own-key flag with an entry waiting: stopping every stall, or withholding in every stall, passed (C) | Medium | T10's `LogFull` test publishes the waiting entry at the `ok` |
| AM11 | A second theft of the new key after a regeneration on the same connection, re-stopping with the new epoch, untested (C) | Low | A test: `after_send` still asks for a new connection |
| AM12 | The slice list put R14's send in (c2) while `after_send` lands here (A) | Low | (c1a) names `after_send` and its `outbox`; the module doc |
| AM13 | On a full log, a `check_own_key` inside `decrypt` failing with `Internal` makes `decrypt` return `Internal`, not `LogFull`: no stall, and a tick's `synced` could pass the push (B) | Far-fetched | None: only libsodium failing, or a reserve of spec 021 R18 used up, reaches it; no adversary of `docs/spec.md` §2 |

**Round 3.** Fresh passes on the whole change. AM1–AM13 hold; pass B found nothing; passes A and C found only test gaps, and no production defect. Pass C ran 46 mutants: 42 killed, 1 equivalent, 3 survived, each killed below. The audit closes with this round (`CLAUDE.md`, the audit).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AM14 | R14's send clauses tested under T10's name, and an entry in flight never shown not to be queued twice (A) | Low | `s028_t14_r14_send` with that clause; the frozen case stays in T10 |
| AM15 | Survivors: a tick without the stalled channel, `after_send` of an unknown channel, `MemoryStore::copy` as a shared handle (C) | Low | One assertion each |

## Audit AL

**2026-10-09 — Audit AL, the code audit of slice (b2) of spec 028-session-sans-io (branch `028-truncation`): the truncation (R8), the `ok` and the two limits of R9, and the `session_on_frame` fuzz target (R3); round 1 of three passes (A: conformance; B: the adversary, a server sending any frame sequence and a clock set back; C: quality, tests and hand mutants).** One High finding, a hole in R16 that the code reproduced. Pass C ran 37 mutants: 27 killed, 2 equivalent, 8 survived; every survivor is killed by a clause added, or made equivalent by AL1.

Decisions taken without the human, by the advisor (`.claude/agents/advisor.md`, three passes): a `synced` that fails goes to `Step.failed` with its value waiting in memory (unanimous), and an `outbox` that fails at the `ok` too, the freeze waiting for slice (c1b) (two to one; the minority's freeze at once closes no privacy hole, the `Device` freezing the channel from `failed`, spec 027 R14); a clock set back counts as past both limits of R9, and the gap's `Reconnect` comes once (unanimous); one `session_on_frame` seed per vector, at `text_k1`'s `now`, with no tick (unanimous). Two passes escalated the seeds' channel; the human sent it back to the advisor's answers, which converged: the seed script retargets the frames and adds the 013 blobs as pushes (AL4).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AL1 | A server's `nonce_expired` naming a subscribed channel (which R4 never sends) unsubscribed it; at the next `ok` the session judged the truncation by the `last` captured at the first `subscribe`, older than the ticks' `synced`, and its `truncated_at` hid a deletion inside the TTL (B) | High | R16 amended: such a `nonce_expired` is a `Reconnect` alone, as a `rate_limited` naming a subscribed channel; this reverses AK7's "removed whatever its state"; T06 |
| AL2 | Tests that pass with the code removed: a failed `synced` and a failed `outbox` at one `ok` (either `failed` push could go), a failed `synced` on a tick; the set-back clause of the silence masked by the gap rule; the `ok` after a truncation found at the `hello` never shown to sync; one channel judged at the `hello`; the re-check by the moved cursor (T08's backlog clause); the gap's `Reconnect` once (A, C) | Medium | T08 and T09 clauses, each checked against its mutant; R9 says the `ok` syncs after a truncation found at the `subscribe` |
| AL3 | `connection.rs` at 600 lines; two lookups in `on_ok`; a fail-open `_ => false` for a channel never judged; a clone of the queue; `last_frame` set at `on_connect`, dead (C) | Low | `connection/event.rs` and `connection/sync.rs`; one lookup; a channel never judged is judged at its `ok`; the decision taken over the pending list; the line removed. AL1 makes the `Found` mark at the `ok` and the in-flight set across two `ok`s unreachable in this slice: the mark is removed, the set waits for the `outbox` of slice (c2) |
| AL4 | The 028 frames name a channel other than `text_k1`'s, so no `session_on_frame` seed passes R9's routing or reaches `decrypt` (A, B, advisor) | Medium | `fuzz_seeds.py` sets every `channel_id` of a 028 frame to `text_k1`'s and adds each 013 blob as a `push`; 028 R3 and 016 R8 amended; no vector changes. T03's clause on a push seed reaching `decrypt` lands with the routing of slice (c1a) |
| AL5 | A device clock that jumps ahead and back leaves `truncated_at` in the future, read as `now` by spec 021's gap rule (B) | Far-fetched | None: no adversary of `docs/spec.md` §2, and spec 021's rule |
| AL6 | The net diff is over AGENTS 14's 400 lines (A) | Low | Justified in the commits and the pull request: about 300 of production code, the rest the tests of R8 and R9, kept whole |

**Round 2.** Fresh passes on the whole change. The round 1 fixes hold; no production defect outside AL7. Pass C ran 64 mutants: 45 killed, 8 equivalent, 11 survived, each killed below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AL7 | A truncation R8 found at the `hello` was not judged again at the `ok`: a `subscribe` held past its TTL by a nonce cycle, a `rate_limited` or a server let the `ok` call `synced` over a stretch that expired while it waited, with the banner's `before` older than the loss (B) | Medium | At the `ok`, such a channel records the truncation again with the `ok`'s `now`, then syncs; R9 and T08 |
| AL8 | The `session_on_frame` seed check rebuilt the expected frame with the function that wrote the seed, so a broken retargeting passed (A, C) | Medium | `fuzz_seeds.py` writes the expected frames apart: the vector frame with its channel replaced for the types that carry one, the push field by field; the five seed mutants fail it |
| AL9 | Survivors: a gap's stop kept on the next connection; the `last` captured at the `subscribe` never shown to clear a truncation at the `ok`; the `Debug` of `HistoryTruncated` and `NotDelivered`; the events of a failed `outbox`; the fuzz session never shown to hold `text_k1`'s channel (C) | Medium | One clause each in T03, T08, T09 and the `Debug` checks |
| AL10 | T09 said a failed `synced` publishes nothing, where R9 and the test publish; R9's "waiting in memory" ignored the reopen of spec 027 R14; T06 did not name AL1's clause; R3's sentence attached its seeds to `decrypt` (A) | Low | T09, R9, T06 and R3 reworded |
| AL11 | `last_call = now` at `on_connect` is an equivalent mutant: nothing is subscribed before a call has run the gap check (C) | Far-fetched | Kept: R5's words; a preference |

**Round 3.** Fresh passes on the whole change. AL1 and AL7 hold; no production defect. Pass B found only AL15, far-fetched; passes A and C found only test gaps and a History line. Pass C ran 84 mutants: 74 killed, 7 equivalent, 3 survived, two killed below and the third AL16. The audit closes with this round (`CLAUDE.md`, the audit).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AL12 | Clauses that could not fail: the order of the truncation and `synced` at the `ok` (only the store shows it), the frame that trips the gap still processed, the value of the stored `truncated_at`, the fuzz entry's `now` (A, C) | Medium | T08 reopens the store after the `ok` and checks `truncated_before` by value; T09 trips the gap with an `ok`; the `session_on_frame` verdict returns the fixed `hello`'s and `ok`'s events too, so a `now` with a truncation fails T03 |
| AL13 | No History line for the round 2 amendments (A) | Low | Added |
| AL14 | `keep_synced` both checks the silence and syncs (C) | Far-fetched | None: a preference |
| AL15 | A clock set back at the `hello` and set right before the `ok` gives a false truncation, and with it no gap counted for a long-silent peer (B) | Far-fetched | None: two clock jumps in one handshake, no adversary of `docs/spec.md` §2; the same family as AL5 |
| AL16 | The one-line `session_on_frame` wrapper is not called by a test, as no target's is (C) | Far-fetched | None: the convention of every target of spec 016 |



## Audit AK

**2026-10-09 — Audit AK, the code audit of slice (b1) of spec 028-session-sans-io (branch `028-connection`): `MemoryServer`, the connection and the subscription (R4–R7, with the session clauses of R1 and R2); round 1 of three passes (A: conformance; B: the adversary, a server sending any frame sequence and a clock set back; C: quality, tests and hand mutants).** No High finding and no production defect. Pass C ran 72 mutants: 37 killed, 8 equivalent, 27 survived; every survivor named below is killed by a clause added.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK1 | Tests that could not fail: T05's `skip` and T06's discard read an `outgoing()` already drained; `ok` → `Subscribed` untested; the refused channel never shown to come again; `Reconnect` on a new connection, the frames left unwritten at a disconnect or an unsupported `hello`, the spacing reset, the release order by cursor and `created_at` (A, C) | Medium | T05–T07 rewritten to assert what they release; `s028_t09_r09_ok_marks_subscribed` |
| AK2 | T06 checked the signature with `auth_message`, the function under test (A) | Medium | T06 builds the §6 bytes by hand |
| AK3 | `MemoryServer` branches untested: the hosts, the nonce's age, `not_subscribed`, `since` and its clamp, the TTL filter, live pushes, `disconnect` (C) | Low | `s028_t04_r04_memory_server_checks` |
| AK4 | A clock set back stalled the queue and the waits of R7 with no `Reconnect` (B) | Low | A time recorded later than `now` counts as long past, as 021 R18 and 027 R12 do; T07 |
| AK5 | Each `nonce_expired` restarted the wait for a `hello`, so a server could hold every channel off (B) | Far-fetched | Fixed anyway: the wait starts only when none runs |
| AK6 | `Event`'s derived `Debug` printed the full `channel_id` (B) | Low | A `Debug` with the 4-byte prefix; T09 checks it |
| AK7 | `nonce_expired` naming a subscribed channel left it subscribed (A); `Reconnect` once per connection was no rule (A) | Low | Removed whatever its state; the once-only flag removed |
| AK8 | Four flags and options for one connection state; a second copy of the `channel_id` derivation; protocol literals repeated; a dead TTL; nine `Event` variants and `Step::failed` with no producer (C) | Low | `enum Link`; one derivation (`ChannelId::derive`, AK11); `CODE_*` in `frames.rs`; variants added by the slices that produce them |
| AK9 | 028 R6 did not name `auth_message`, which 031 R2 asks it to sign; R7's clause on a subscribe queued again after `rate_limited` deferred without a word (A) | Low | R6 amended, 031 History; the module doc names the clause for slice (d), whose `rate_limited` alone reaches it |
| AK10 | `docs/spec.md` §9 still sketches a `pub` `Session` and `Channel::auth_subscribe` (A) | Low | Left: spec 027 brings §9 up to date (audit S) |

**Round 2.** Fresh passes on the whole change. No production defect; the round 1 fixes hold. Pass C ran 59 mutants: 48 killed, 3 equivalent, 8 survived, each killed below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK11 | The derivation of AK8 was `config::channel_id_of`, where spec 031 R3 names it `ChannelId::derive` (A) | Low | Renamed; 031 History |
| AK12 | AK5's fix departed from R7 and R16 as written (A) | Low | R7 and R16 amended: a `nonce_expired` does not restart a running wait |
| AK13 | `MemoryServer`'s docs claimed every check of 031 R5; it has neither `bad_ttl` nor the previous nonce's window (A, C) | Low | Docs say the two checks it makes |
| AK14 | Survivors: `synced_at` in the release order (a future one ignored, `max` with the cursor); one `Reconnect` past the nonce window; a valid frame of another type ignored; the test server's nonce renewal and its 60 000 ms edge; distinct `server_id`s (C) | Low | One clause each in T04, T06, T07, T09 |
| AK15 | Constants and `last_complete` wider than needed (A, C) | Nit | Private |
| AK16 | Clock set back: a new `hello` can release two subscribes less than 1 100 ms apart; a repeated nonce restarts the client's window; a 1 ms step back during a wait gives a `Reconnect` (B) | Far-fetched | None: a `rate_limited` or a reconnect at most, the AK4 rule as decided |
| AK17 | The queue outside `Link::Ready` makes two of its clears equivalent mutants (C) | Far-fetched | Kept: they are R16's and R5's words; a preference |

**Round 3.** Fresh passes on the whole change. No production defect. Pass C ran 50 mutants: 43 killed, 1 equivalent, 6 survived; five are killed below, the sixth (no clear of the queue at `nonce_expired`) is equivalent, as AK17.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK18 | The clock-set-back rule of AK4 was in the code, not in R7 (A) | Low | R7 says how such a time counts; T07 names its clauses |
| AK19 | An unnamed `nonce_expired` kept the queue and started no wait (A, C) | Low | It discards the queue and starts the wait as a named one, then `Reconnect`; T07 |
| AK20 | Spec 011 did not name `ChannelId::derive`, which 031 R3 asks it to (A) | Low | 011 R8, Interface and History |
| AK21 | Survivors: a `synced_at` equal to `now`; a channel closed before its release; the window passing within 1 100 ms of a release; the `Debug` of `Reconnect` and `UnsupportedServer` (C) | Low | One clause each in T06, T07, T09 |
| AK22 | The 028 Interface named `testing.rs` for `MemoryServer` (A) | Nit | `testing/server.rs` |
| AK23 | A channel id repeated in `Session::new` would be subscribed twice (B) | Far-fetched | None: no input reaches it; the `Device` opens each channel once |

**Round 4.** Fresh passes on the whole change. No production defect; pass B found nothing.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK24 | After `UnsupportedServer` a bad frame gets no `Reconnect`, as 027 R11 wants, but R1 read alone asked for one (A) | Low | R2 says frames are then ignored with no event; T02 |
| AK25 | `Event` derives `PartialEq` and `Eq` that only the tests use; T09's push of an unknown channel cannot fail until pushes are routed (A) | Far-fetched | None now: `Received` already compares; the slice that routes pushes checks a known channel's |
| AK26 | Survivors: a named `nonce_expired` also giving `Reconnect`; `max(cursor, synced_at)` with the cursor the larger; `since` taken from `synced_at` (C; 94 mutants, 88 killed, 3 equivalent) | Low | One clause each in T06, T07 |
| AK27 | `Link::Unsupported` behaved as `Closed`; `id_prefix` copied `key_prefix` (C) | Low | One `Closed`; `key_prefix` takes a slice |

**Round 5.** Fresh passes on the whole change. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK28 | `docs/spec.md` §2 and `docs/threat-model.md` promised that one connection per server does not reveal its number of channels; one `subscribe` and one `ok` per channel, 1 100 ms apart, show it through TLS, and an absent `since` marks a new or imported channel by size (B) | Medium | Three advisors escalated, all recommending the second option; the human reviewer took it (decision): the observer row says the count shows, `since` is always sent (0 with no cursor) so every `subscribe` has one size; 028 R6, T06 and Security amended; cover traffic stays v2 |
| AK29 | A stale `tests.rs.orig` committed in round 4, read by the requirement gate (A, B, C) | Low | Removed |
| AK30 | A second `hello` never shown to set the nonce and window of the `subscribe`s a tick releases: three survivors (A, C; 64 mutants, 59 killed, 2 equivalent) | Medium | T07 checks the signature of a tick-released subscribe over the second nonce, late in its window |
| AK31 | `Subscription` derived traits nothing uses; `key_prefix`'s doc and the test module's doc out of date (A, C) | Nit | Removed; reworded |

**Round 6.** Fresh passes on the whole change. No production defect; pass B checked AK28 from the observer's side (every `subscribe` one size); pass C ran 73 mutants, 71 killed, 2 equivalent, none surviving.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK32 | T06's doc comment still said `since` is absent with no cursor; T07 did not name the AK30 clause (A, B, C) | Nit | Reworded, in the test and in 028 T07 |

**Round 7.** Fresh passes on the whole change. Passes A and B found nothing but two far-fetched points (a 028 History line for round 6, two lines over 100 columns that no check enforces), fixed anyway; pass C found test gaps only, no production defect (30 mutants: 20 killed, 4 equivalent, 6 survived). The audit ends here, as `CLAUDE.md` says for such a round, once the tests below killed the survivors and the local CI was clean.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AK33 | Survivors: a `nonce_expired` naming a channel that had its `ok`; a session subscribing channels not its own; an `ok` arriving while a fresh `hello` is awaited; the test server's `ack` before its echo and the echo itself; two subscriptions catching up at once; a `subscribe` without `since` (C) | Low | One clause each in T04, T06, T09 |

## Review during development

**2026-10-09 — Decision of the human reviewer: until the first release, the audit of `CLAUDE.md` replaces the human review before merging.** The human still accepts every spec before it is implemented, decides what an audit escalates and approves every ADR; the human review before merging returns at the first release. `AGENTS.md` "Per-feature flow", `docs/spec.md` §10 "Per-feature flow" and governance, the `architecture` skill and `.github/CODEOWNERS` say so. GitHub required no approving review on `mvp` already (0), so its settings do not change.
## Audit AJ

**2026-10-09 — Audit AJ, the code audit of slice (a) of spec 028-session-sans-io (branch `028-frames`): the frame codec, `028.json` and the `frame_decode` target (R1, R2, R3's first target); round 1 of three passes (A: conformance; B: the adversary, a server or an observer sending any frame; C: quality, tests and hand mutants).** No High finding. Pass C ran 40 mutants: 29 killed, 3 equivalent, 8 survived, each killed by a clause added below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AJ1 | `docs/spec.md` §6 was never brought up to date when 028 was accepted: `ok` with `has_more` and `oldest_retained_at`, `error` without `channel_id` and `client_ref`, a fresh `client_ref` per publish, pages of 500 (A) | Medium | §6 brought up to date as 028 "Public API changes" says |
| AJ2 | `encode` returned its 70 000-byte buffer, so every queued frame held 70 KB, past the 4 MiB send-queue bound of §6 on a server using this encoder (B, C) | Medium | The frame copied at its length; T01 checks the capacity |
| AJ3 | Survivors: trailing bytes after the last field, an unknown `type` with an `ok`'s key 1, a malformed optional key read as absent (`since`, `error.channel_id`, `error.client_ref`), the publish blob bound, the encode capacity at the limit, `frame_decode_verdict` (C) | Medium | T01 asserts every one-byte-short field and gains the cases; a `hello` of 69 998 and 70 003 bytes; 016 T08 checks the verdict; `type_unknown` carries a key 1 |
| AJ4 | 030 R14 and T14 cannot hold for `ok_unknown_key`, a decode case no encoder writes (A) | Low | 030 R14 and T14 leave it out |
| AJ5 | Three `origin` texts read "a ok", "a ack", "a error", in a file about to freeze (A) | Low | "the … frame with every key" |
| AJ6 | `Frame` derived `Clone`, which nothing uses and the Interface does not name (A) | Low | Removed |
| AJ7 | `MAX_BLOB`, the spec 013 envelope bound, lived in `storage::state::items` (C) | Low | Moved to `proto::envelope` |
| AJ8 | `is_supported`'s lower bound is dead (an empty list contains no 1); `bytes64` rewrote `any::<[u8; 64]>()` (C) | Nit | Removed |
| AJ9 | `Debug` prints `sig` and blobs; `error.message` may hold control characters (B) | Far-fetched | None: no secret, and no path shows `message` in this slice; spec 056 must not render it |

**Round 2.** The same three passes, fresh, on the whole change. No production defect; the round 1 fixes hold. Pass C ran 19 mutants: 13 killed, 1 equivalent, 5 survived, each killed by a clause added below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AJ10 | The new §6 cursor sentence left out 021 R20's exceptions (a store failure, a push expired by the local clock) and said "at most once a minute" (A, B) | Low | §6 reworded after R20 |
| AJ11 | §6 streams the whole backlog before `ok` but its limits row still closed at 4 MiB, without 028 R4's exemption (B) | Low | The row names the exemption and 030 R8 |
| AJ12 | §6 gave `proto_versions` as `[uint], ≤ 8` and left out the empty list (A) | Low | `list of u8`, 1 to 8 items accepted, R2 cited |
| AJ13 | `encode` still allocated and wiped 70 000 bytes for every frame (B) | Low | The writer sized at the frame's length with `record_len` and `list_len`, as spec 020 R25 |
| AJ14 | Survivors: an absent `since` written as 0, `since` 0 dropped or read as absent; a target's `[[bin]]` removed from the fuzz manifest (C) | Low | T01 re-encodes every frame without an optional key and holds a `since` of 0; 016 T02 gains `s016_t02_r02_every_target_is_a_bin` |
| AJ15 | `error_reference` paired `channel_quota` with a text 030 R13 does not send (A); 016 T08 did not name its frame clause (A) | Nit | "channel full"; T08 and History amended |

**Round 3.** Fresh passes on the whole change. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AJ16 | The §6 limits row said 030 R8 bounds the backlog; R7 paces it a page at a time and R10 exempts it; the diagram left out the held pushes (A, B) | Low | Row and diagram reworded |
| AJ17 | §9 named 020 and 030 as the specs that define the `pub` functions the server reaches, not 028 for `Frame` (A) | Low | 028 named |
| AJ18 | The 028 Interface did not list `session/frames/tests.rs` (A) | Nit | Listed, with a History line |
| AJ19 | The slice is about 1 000 net lines, over AGENTS 14 (A) | Low | Justified in the PR: one codec with its vectors and target, tests not trimmed |
| AJ20 | Survivors: an absent optional key still counted in `encoded_len`; `proto_versions` decoded with a bound below the frame's 13 990 items (C) | Low | T01 checks the capacity of a frame without an optional key; T02 decodes 13 990 versions |
| AJ21 | `record_len`'s doc said every caller bounds its values first; `Frame::encoded_len` relies on the saturation (C) | Nit | Reworded |

**Round 4.** Fresh passes on the whole change. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AJ22 | 030's Vectors section still said the server reproduces every server-direction frame, against R14 as AJ4 amended it (A) | Low | Reworded as R14 |
| AJ23 | The §6 truncation sentence left out R8's rule that a `synced_at` later than `now` is ignored (B) | Low | Added |
| AJ24 | The publish blob bound was not tested at `MAX_BLOB`, in decode or encode: two survivors (C) | Low | A `publish` of `MAX_BLOB` in T01's `at_bounds` |
| AJ25 | The AJ21 rewording left a 124-character line; `Writer::with_capacity`'s doc said `max` is never an unbounded length (A, C) | Low | Rewrapped; the doc names a length checked against the schema's maximum |
| AJ26 | §9's "their own specs" did not fit 028 (A) | Nit | "that a spec defines" |

**Round 5.** Fresh passes on the whole change. No finding in any pass; pass C ran 21 mutants, 17 killed and 4 equivalent. The audit ends here.

## Spec 026 implemented

**2026-10-09 — Spec 026-peer-limits is `implemented`.** Its acceptance criterion is automated alone: `cargo test -p privatechat-core s026_`, clippy and the documentation lint are green on `mvp` (9137d6a), after the eight rounds of Audit AI, which the human reviewer closed at round 8.

## Audit AI

**2026-10-09 — Audit AI, the code audit of spec 026-peer-limits (branch `026-peer-limits`, PR #47), round 1 of three read-only passes (A: conformance with R1–R7 and T01–T07; B: the adversary, an intruder with the leaked config minting keys, a server choosing every `received_at` and `server_id`, a wrong device clock; C: code quality, tests and hand mutants).** No High finding and no production defect. The human reviewer took the recommendation of each of the three decisions (AI1–AI3). Pass C ran 33 mutants beyond the author's 29: 25 killed, 8 survived, each killed by a test added below.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI1 | An eviction erases an unknown's gap, so a server dropping its messages with an intruder flooding keys hides the deletion (B1) | Low | Residual in 026 Security (decision) |
| AI2 | `last_seen` is the device's `now`: a clock set back evicts a newcomer first; ties can be ground for (B2, B3) | Low | Residual in 026 Security (decision) |
| AI3 | The rejected key is counted before the cursor commit, which may fail (A3, B5, C12) | Info | Left, with a comment: the set counts distinct keys (decision) |
| AI4 | `docs/spec.md` §7 lacked the muted exception decided in audit J and the per-session count; 022 kept "until it is implemented" (A1, A2, B4) | Low | §7 and 022 amended |
| AI5 | Tests a mutant survived or a clause the spec names: the own-key outcome, a refused label on a counted channel, the peers-changed flag, a stale and a `key_retired` newcomer at the limit, a verified or retired peer counted in the labelled budget, the evicted key counted and not the newcomer, a second gap that stays, gaps a failed commit keeps, the room check after the retired check and before step 6, 1 024 pinned, the 551st pre-verification committing nothing, an oracle that copied the rule (A4–A6, B7, C2–C6, C14–C16) | Medium | One clause each in `tests/limits.rs` |
| AI6 | Docs: the module claimed nothing removes a named peer; `creates` and `check_label` undocumented; the eviction an associated function with no `self`; why the eviction precedes the push (A7, C1, C7, C9–C11) | Nit | Reworded; a free `evict_stranger`; comments |

**Round 2.** The same three passes, fresh, with the agents of `.claude/agents/`, on the whole change. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI7 | `docs/spec.md` §7 said no key can be labelled at 500, and that new keys are rejected only when all 50 are muted; 022 gave a stale reason for `label`'s `now` (A) | Low | §7: no unknown key, and the 550 case; 022 reworded |
| AI8 | `forget` of a retired record lets its stolen key write again as an unknown, and R4's hard limit leads the user to forget (B) | Low (partly far-fetched: the user's own call) | 026 Security; the wording is spec 055's |
| AI9 | Five mutants survived: a known peer at the all-muted limit, labelled peers counted against the 50 in the room check and the eviction, a retired unlabelled peer counted as entering, `verify_scanned` of an existing unknown, the order name–collision–admission at the limit (C) | Medium | One clause each in T02–T04 |

**Round 3.** Fresh passes on the whole change. No production defect; one finding changed a rule.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI10 | A clock that ran ahead leaves strangers stamped in the future; once it is corrected they look newest for years, so one fresh key evicts each real newcomer instead of fifty, and the AI2 text ("until the clock is right again", "no more than a plain flood") was wrong (B) | Low | R3: a `last_seen` later than `now` ranks oldest; T03; Security and §7 reworded. Three advisors: all three escalated, two recommended the rule and one the text alone; the human reviewer took the rule (decision). Clamping the stamp to `now`, as 021 R24 does for `truncated_at`, was rejected: it keeps the stamped strangers newest |
| AI11 | 026 History had no line for round 2; the Interface left out `status.rs` (A) | Nit | Added |
| AI12 | Four mutants survived: `forget` removing other records, a muted stranger entering the labelled budget, the total confused with the labelled budget in the room check and in the eviction (C) | Medium | One clause each in T02–T05 |
| AI13 | R4's "create a record when 550 exist" is unreachable with at most 50 unknowns, and its test plants 51 (C) | Far-fetched | Kept, as R4 names it; the test says the state is planted |

**Round 4.** Fresh passes. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI14 | R3, §7 and the `evict_stranger` doc gave a clock that was ahead as the only source of a stamp later than `now`, and Security put the "newcomer looks oldest" case while the clock is behind, where it is the newest; it holds after the correction, unseen by `clock_off` (A, B) | Low | R3, §7, the doc and Security reworded |
| AI15 | T03's "never itself" no longer reached the hazard under the amended R3; pushing the newcomer before the eviction survived (A) | Medium | A clause with every stranger at the same `now` and the newcomer's key the smallest; T03 reworded |
| AI16 | Five mutants survived: the server's `received_at` passed to the eviction, `first_seen` in the key, a slack in the comparison, `last_seen` kept by `update_peer`, `forget` removing every labelled record (C) | Medium | The future-stamp clause rewritten (`ahead` 0 and a year, `first_seen` before the jump, a stranger writing again, a `received_at` behind); a labelled bystander in T05 |

**Round 5.** Fresh passes. No production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI17 | 021's Context still said the hooks of 024 and 026 change nothing until implemented (A) | Low | Removed, with a History line |
| AI18 | Five mutants survived: the sender's `sent_at` passed to the eviction, off-by-ones at 549 peers in the room check, the eviction and `admits_labelled`, `forget` counting its key as ignored (C) | Medium | A backdated `sent_at` in the future-stamp clause; 549-peer rows in T02 and T03; a 550th pre-verification admitted in T04; `ignored_keys` read in T05 |
| AI19 | A muted known stranger writing at the limit could be made to evict (C, contrived mutant); an eviction ends `short_collides` against the evicted stranger, which a key ground to its 4 words (about 2^44 tries) and a flood could use (B) | Far-fetched | A clause in T03 for the first; the second listed here, unknowns carrying no trust (spec 014) |

**Round 6.** Fresh passes: A and B found nothing; C, no production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI20 | The 1 024 cap was pinned only through a direct `ignore_key` call: inlining it as a bare insert at the rejection or the eviction, which would let a flood grow the set without bound, survived; `forget` dropping a counted key from the set survived (C) | Medium | A T06 clause with a full set through a rejection and an eviction; a T06 clause forgetting a counted key |

**Round 7.** Fresh passes: A found nothing; B one far-fetched finding; C no production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI21 | `unknown_limit_reached` was read only with 50 unknowns, so a flag written as "50 muted" survived at 550 in all (C) | Low | T02 checks the flag on every row |
| AI22 | An eviction or a `forget` rewritten as a `swap_remove` reordered the records, which spec 022 R3 and R13 read for ties of `first_seen` (C) | Low | A T03 test of the order after both |
| AI23 | `SessionCarry` derives `Debug` over full keys, now up to 1 024 ignored ones; nothing formats it today (B) | Far-fetched | Listed; spec 027 or 028 redacts it if they ever log it |

**Round 8.** Fresh passes: A and B found nothing; C no production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AI24 | The server's `received_at` was tested only behind `now`: taking the later of the two clocks in the eviction, which would let a server stamping ahead restore the shield R3 removed, survived; a pre-verified key's first message treated as a new peer survived (C) | Medium | The future-stamp clause runs with a `received_at` two years ahead too; a T03 clause for a pre-verified key's first message |
| AI25 | `labelled_limit_reached` as `!admits_labelled(true)` differs only with more than 50 unknowns (C) | Far-fetched | Listed (as AI13) |

Left as they are: the third copy of "remove a record, then its gap" (C8), one line at each place; `unknown` and the test `text` helper not shared with other test files (C17); the O(550) counts per new key (C13), below the cost of the signature check and the state rewrite.

## Spec 025 implemented

**2026-10-09 — Spec 025-identity-regen is `implemented`.** Its acceptance criterion is automated alone: `cargo test -p privatechat-core s025_`, clippy and the documentation lint are green on `mvp` (4da62ee), after the two rounds of Audit AH.

## Audit AH

**2026-10-09 — Audit AH, the code audit of spec 025-identity-regen (branches `025-identity-regen` and `025-retirement`, PRs #42 and #43), round 1 of three read-only passes (A: conformance with R1–R8 and T01–T08; B: the adversary, a server choosing every `received_at` and the timing of acks, an intruder with the config, a thief of the old key, a wrong clock; C: code quality, tests and hand mutants).** One High finding (AH1), no production defect beyond it. The human reviewer took the recommendation of each of the four decisions (AH1–AH4). Pass C ran 27 mutants: 15 killed, 4 equivalent, 8 survived, each killed by a test added below; the author's mutants of the round-1 changes are killed too, but for `retiring_seed.is_some()` in `is_retiring`, equivalent since no old-key entry is left once it is cleared.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AH1 | R5 took an `ack` stored up to `ttl_ms + 360 000` after `sent_at` as delivered, without R17's `sent_at + ttl_ms ≥ now`: a retirement stored past its life, which no member shows, erased the old seed and cleared "retirement pending" (B1) | High | R5 judges it as R17 does an ordinary entry (ADR 0044); otherwise `Ignored` and re-sealed the next minute (decision, 025-R3); 025 added to ADR 0044's affected documents (a stale reference) |
| AH2 | R4 re-sealed, and committed, every minute a copy held back behind the old key's entries, against `docs/spec.md` §4 and §7 and ADR 0034, "when it is handed out" (A2, B3) | Low | Re-sealed only as `outbox` hands it out (decision); 021 R22 names the copy R4 holds back (A4) |
| AH3 | `is_retiring` derived the old key's public key from the old seed at every push, against R7 (A1) | Medium | The last of `own_old_keys` tells it; R7 says so (decision) |
| AH4 | Residuals not written: an old key dropped while its later `key_retired` copy is still accepted (A3); a short TTL leaves a retirement less than a minute of life (B2); a thief of a dropped old key reads as an unknown peer (B5); a stuck retirement blocks a second regeneration (B6) | Low | 025 Security (decision) |
| AH5 | R1's "the oldest" of `own_old_keys` read by list order, which the code and test pinned and the text did not say (A, question) | Nit | R1 and Limits: the first in the order of regeneration |
| AH6 | `OldKey` derived a `Debug` printing the whole key (B4) | Low | Manual `Debug` with the 4-byte prefix (AGENTS 19), tested in T06 |
| AH7 | Tests a mutant survived or a clause the spec names: the re-seal's signer, a fresh nonce, a delivery that wiped the current key's entries, `server_id`, 15 old keys, the retirement out in the call that expires the last old entry, R1's `now` (021 R25), the cursor a re-seal commits, the retiring key among two old keys, a delivery after a reopen, T08's re-seal under its own name (A5, A6, A8, A9, C1–C9) | Medium | One clause each in `tests/regen.rs` |
| AH8 | A late `ack` of the current copy returned `sent_at: None`, which spec 028 R12 needs to hold that copy (A7, C10) | Low | `sent_at: Some`; the field's doc names the earlier copy |
| AH9 | Docs and duplication: `acked`'s doc, `# Errors` of an epoch overflow, "oldest first", the marking comment, the minute rounding in three places (A10, A11, C11, C12, C15, C17, C18, C20, C22) | Nit | Reworded; `minute_of` shared; `NONCE_RANGE` reused by the test |

**Round 2.** A fresh reading of the final state with the round-1 fixes: no Blocker, High or Medium finding.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AH10 | The docs of `AckOutcome::Ignored` and `RetirementDelivered` still read as before AH1 (R2-1) | Low | Both name R5's "in time" |
| AH11 | T04's backward re-seal checked `sent_at` alone; no test pinned `sent_at: None` for an earlier copy's `ack` (R2-2, R2-3) | Nit | Nonce and `client_ref` asserted; `None` asserted |
| AH12 | `docs/spec.md` §4 read as if the copy were re-sealed "before the stale check", and re-sealed "in the next minute" after a late `ack`, while R4 re-seals it only as it is handed out (R2-4) | Nit | §4: never judged stale, sealed again when next handed out in another minute |

Spec 028 R12 and R16 hold an ignored copy "until its next re-seal or until the minute changes"; under R4 only the minute change releases it, which 028 may say when it is implemented (R2-5).

Left as they are: `seal_retirement` repeats `encrypt`'s sealing and the `LogFull → Internal` closure is in two places, below the third caller (C13, C14); the old key derived twice in R1 (C16); `OldKey` beside `Gap` in `channel.rs` (C19); the test helpers of `tests/regen.rs` not shared (C21). M13 of pass C, the re-seal without its kind check, is equivalent once R4 re-seals only a copy no old-key entry precedes.

## Spec 025 open questions

**2026-10-09 — The open questions 025-R1 and 025-R2 of spec 025-identity-regen (Audit AD, AD14) are closed before its implementation.** Both need an entry `under_retired_key` beside a `key_retired` copy that has left, or beside a second old key's entries, and spec 025 already rules both out: R4 hands out no copy of the `key_retired` while an entry `under_retired_key` is still in the `outbox`, no entry is marked after R1, and R1 refuses a second regeneration until R5 has removed the `key_retired`. The echo of a superseded copy therefore finds nothing to remove, and the flag always names the key being retired. The human reviewer took the recommendation: no new field and no kept signatures for superseded copies; the reason goes into 025 Security, and T01 and T04 pin it. Spec 021 T09 keeps its planted state, which tests step 5 alone.

## Spec 024 implemented

**2026-10-06 — Spec 024-key-retired is `implemented`.** Its acceptance criterion is automated alone: `cargo test -p privatechat-core s024_`, clippy and the documentation lint are green on `mvp` (b6c1173), after the two rounds of Audit AG.

## Audit AG

**2026-10-06 — Audit AG, the code audit of spec 024-key-retired (branch `024-key-retired`, PR #39), round 1 of three read-only passes (A: conformance with R1–R6 and T01–T06; B: the adversary, a server choosing every `received_at` and `server_id`, an intruder with the config, a thief of a member's key and of one's own; C: code quality, tests and hand mutants).** No High or Medium finding and no production defect. Pass C ran 27 mutants: 20 killed, 2 equivalent, 5 survived, each killed by a test added below. The human reviewer took the recommendation of each of the three decisions (AG1, AG2, AG3).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AG1 | A flood that keeps the log near full holds a trusted peer's retirement at `LogFull` until it may expire on the server; one's own key alone has a full-log exemption (B4) | Low | Accepted residual, 024 Security (decision) |
| AG2 | R2's "no event follows" while removing a record sets the peers-changed flag of 021 R1, which a client reads as a refresh (A-A) | Nit | R2: no message event, the flag on a removal (decision) |
| AG3 | R2 lists what changes for a muted unknown without `last_seen`, which the code moves as 022 R2 says (A-B) | Nit | R2 names `last_seen` (decision) |
| AG4 | `retire` did not record its `now` (021 R1) (A2, B7) | Low | Recorded; `label`, `verify` and `verify_scanned` of spec 022 share the gap, left to a PR of their own |
| AG5 | The 013 vector check read every `Ok(None)` as "message" (A1, B2, C5) | Low | Only for the two `key_retired` vectors |
| AG6 | The Interface change had no History line (A3); `consume_retirement` had no `# Errors`; `update_peer` kept its own lookup (C1, C2) | Nit | History line; `# Errors`; `peers::find` |
| AG7 | Test gaps: the cursor-only commit of a stranger's retirement, `verified` alone and `last_seen`, `read_only` after an own-key text, a retirement that expires before it is shown, a received retirement under `FailingStore`, the R24 gap check from an unknown that R2 now removes, a single commit with its seen record (mutants M08, M11, M22, M24, M25; A4, B1, B3, C7) | Low | T01–T03, T06; `s021_t24` labels the sender |

**Round 2.** Two passes: a fresh reading of R1–R6 with the round-1 fixes, conformance and adversary together, which found them correct and complete; and 34 hand mutants of the code spec 024 added or changed, 20 killed, 3 equivalent, 1 not compiling, 10 test gaps and no production defect. The human reviewer took the recommendation of the one decision (AG8).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AG8 | A removed record's in-session gap stayed behind: throwaway keys that leave a gap and retire themselves could pile up gaps until the lock (R2-1) | Low | 021 R24: a gap goes with its peer's record; `s021_t24` (decision) |
| AG9 | A muted unknown that retired itself and is labelled later reads `Replay`, not `RetiredKey` (R2-2) | Nit | Within the price R2 states; none |
| AG10 | Test gaps: `retire` recording its `now` when refused, a trusted retirement's listed time and seen record life, `retired_at` and `last_seen` from `now` and not `received_at`, a muted unknown among other peers, a stranger's second copy in the same minute, the gap test's peer order (mutants N01, N02b, N09, N11–N13, N17, N18, N34; R2-3) | Low | T01, T02, T04; `s021_t24` |

## Spec 023 implemented

**2026-10-05 — Spec 023-ttl-purge is `implemented`.** Its acceptance criterion is automated alone: `cargo test -p privatechat-core s023_`, clippy and the documentation lint are green on `mvp` (889809c), after the two rounds of Audit AF.

## Audit AF

**2026-10-05 — Audit AF, the code audit of spec 023-ttl-purge (branches `023-a` and `023-b`, PRs #35 and #36), round 1 of three read-only passes (A: conformance with R1–R7 and T01–T07; B: the adversary, a server choosing every `received_at`, an intruder with the config and a flood; C: code quality, tests and hand mutants).** No High or Medium finding and no production defect. Pass C ran 21 of its 86 mutants before it was stopped; the fixes were then checked with mutants of their own. The human reviewer took the recommendation of each of the three decisions (AF1, AF2, AF3 with AF4).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AF1 | A delivered own row tied at the position of its message record, while a client moves it at its `ack`: a repaint could reorder it against a peer's row of the same display time (A5) | Low | R2: ties at the acked record's position; T02 (decision) |
| AF2 | `relieve_headroom` stored a future last compaction as `now`, holding both compactions off ten minutes with no attempt made, against 023 R5 (B2) | Low | A future attempt holds nothing off and is not reset; one `compaction_held_off` for both; 021 R18 and T18 amended (decision) |
| AF3 | The ten-minute bound restarts on a channel reopened after a failed compaction (B1) | Low | R5 says the probe of spec 027-core-api R12 bounds the retries then (decision) |
| AF4 | Text: a late `ack`'s `server_id` is not kept (A-A2); the read-only calls take a `now` and record none for 021 R1 (A-A3) | Nit | 023 R3, 021 R1 (decision) |
| AF5 | `message` derived the signing key, swallowing its error, and built every fate, against R7's "cannot fail" (A1, B5, C5) | Low | An own row needs no key: one fate, no libsodium |
| AF6 | `Stranger`'s `Debug` printed the 4 words, 44 bits of the fingerprint (B3, C9) | Nit | Left out (AGENTS 19) |
| AF7 | `messages` computed a fingerprint and a peer lookup per stranger row (B4) | Nit | One fingerprint per stranger, the peer keys once per call |
| AF8 | The `Context` built with a `'static` base and struct update; `fold_fate` an associated fn with no `self`; the pending window retyped as 420 000; the content of a `Received` built apart from the list's (C4, C6, C7, C8) | Nit | Free functions; the window from `accept_window` and the grace minute; `Received` takes `content_of` |
| AF9 | Test gaps: the attempt instant, a peer row received after its `sent_at`, a stranger claiming one's own name, a `key_retired` row, an expired delivery record in the count, the open check through the log, T07 after the `ack`, an oracle from the production formula (C1, C12, C13, C16, A3, mutants P37, P54, P57) | Low | T01–T05, T07 |

**Round 2.** Two passes: a fresh reading of R1–R7 with the round-1 fixes, conformance and adversary together, which found them correct and complete (a delivered row's tie position survives compactions and reloads, since an acked record shares its message's `purge_at`; each clock setback allows at most one extra attempt); and 98 hand mutants of the code spec 023 added or changed, 88 killed, 5 equivalent, 5 test gaps and no production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AF10 | `contents` and `listing` kept a `Result` that can no longer fail after `content_of` | Nit | Infallible |
| AF11 | Test gaps: a stranger's later rows without their 4 words, every message at one log position, a `purge_at` equal to `now` counted as expired, `purge_expired` and `relieve_headroom` not recording their `now` (021 R1, R25), the tie not checked after a reload and a compaction | Low | T02–T05; their text amended |


## Spec 022 implemented

**2026-10-05 — The non-automatable acceptance criterion of spec 022-peers-tofu: a second check of `INVISIBLE` against `UnicodeData.txt` and `DerivedCoreProperties.txt` of Unicode 17.0.0.** The human reviewer took the independent rebuild of pass C of Audit AE as that check: from its own download of the two files, Cf with its `First`/`Last` ranges expanded, `Default_Ignorable_Code_Point` and the five code points R5 lists, it computed the same 26 ranges, and the pinned toolchain's `char::UNICODE_VERSION` is 17.0.0. `cargo test -p privatechat-core s022_`, clippy, `cargo deny` and the documentation lint are green on `mvp` (6dc66dc). Spec 022 is `implemented`.

## Audit AE

**2026-10-05 — Audit AE, the code audit of spec 022-peers-tofu (branches `022-a` to `022-c`, PRs #30–#32), round 1 of three read-only passes (A: conformance with R1–R16 and T01–T16; B: the adversary, an intruder with the config, a malicious server and a confused user; C: code quality, tests, hand mutants and an independent rebuild of `INVISIBLE`).** No High finding. Pass C rebuilt `INVISIBLE` from its own download of the Unicode 17.0.0 files and found it equal range by range; the human check of the acceptance criterion is still due. The human reviewer took the recommendation of each of the four decisions (AE1, AE3, AE6, and the text of AE12–AE14).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AE1 | `to_lowercase` picks ς or σ from the letters around it, and `name_key` removes the white space first, so "ΝΊΚΟΣ Π" did not collide with "Νίκος Π": caps lock alone escaped the warning and `LabelInUse` (B1) | Medium | R4: U+03C2 read as U+03C3 after lowercasing; ADR 0043 and `docs/spec.md` §7 amended; T04 (decision) |
| AE2 | The derived `Debug` of `Peer` printed the label, the suggested name and the full `pk`; that of `Sender`, inside `Received`, the full `pk` (A2, B2) | Medium | Hand-written `Debug`: the 4-byte prefix of a key, no name (AGENTS 19); T06 |
| AE3 | An unknown key withdraws `claims_name_of` by sending a blank or another name, while its earlier message still reads as the imitated name (B3) | Low | Security: a stated residual, the unknown mark staying on every message (decision) |
| AE4 | "Unknown" was computed without "not verified", true only through the invariant that a verified peer has a label (A1) | Low | `is_unknown`: no label, not verified, not retired; T13 plants a verified record with no label |
| AE5 | The admission hook of spec 026-peer-limits was called for every target, so a relabel at the labelled limit would be refused once 026 lands (A3) | Low | Called only for an unknown peer or a new record |
| AE6 | `label` and `verify` commit an unchanged peer, where `mute` does not (A-Q2, B6, C18) | Nit | Kept: R7 and R8 say to commit, and only the user can cause it (decision) |
| AE7 | Tests that a mutant survived: the Unicode lowercase (ASCII pairs only), `MAX_NAME` in bytes, the order `BadPayload` before `LabelInUse`, the ignored label of R8, a known unlabelled peer scanned with a held label, C1 controls, a changed bound of `INVISIBLE`, an empty key matching an empty key in R13 and R14, T08's flags (C1–C6, C12, C14, A4, A5) | Low | T04–T09, T13, T14: the cases added; T05 pins 4 209 code points |
| AE8 | T16 compared unrelated strings, which almost never collide (C13) | Nit | T16 also disguises a string by case, white space and an invisible character |
| AE9 | `peers()` built every name key once per pair and a QR per peer, 40 lines in one closure (A, B5, C7, C8) | Low | Keys and 4 words computed once per call; one `listed` helper; one collision predicate |
| AE10 | `!name.is_empty()` could never decide (C10) | Nit | Removed |
| AE11 | Doc nits: a bullet of `INVISIBLE` mixed the blanks with the default ignorables; a broken module doc; `verify_scanned`'s errors (C17) | Nit | Reworded |
| AE12 | The Interface named `session/peers.rs` and neither `names_collide` nor `shown_name` (A-Q1, C11) | Nit | Interface amended |
| AE13 | Ties in `first_seen` fell back to storage order unstated (A-Q3) | Nit | R3, R13: ties in creation order |
| AE14 | A blank name replaces the previous suggested name (A-Q4) | Nit | R2 says so |

**Round 2.** Two passes: a fresh reading of R1–R16 with the round-1 fixes, conformance and adversary together, which found the fixes correct and complete; and 124 hand mutants of the code spec 022 added, 109 killed, 6 equivalent, 1 that did not compile, 8 test gaps and no production defect. The human reviewer took both recommendations (AE15, AE17).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AE15 | A Turkish caps lock writes ı as I and i as İ, so "IŞIK" did not collide with "Işık" nor "İNCE" with "ince", the same class as AE1; it is the only other context or locale case of `to_lowercase` that removed spaces or caps lock reach | Low | R4: İ read as I before the lowercase, ı as i after it; ADR 0043 and §7 amended; T04 (decision) |
| AE16 | `Gap`, public through spec 028's event, still derived a `Debug` with the full `pk`, and with it `SessionCarry` | Low | Hand-written `Debug` with the 4-byte prefix; T06 |
| AE17 | Capitals written without their accents ("ELODIE", Greek capitals without the tonos) do not collide, a residual of no normalisation that ADR 0043 did not name | Nit | ADR 0043, Security and §7 name it; T04 pins "Élodie"/"ELODIE" and "Νίκος"/"ΝΙΚΟΣ" (decision) |
| AE18 | Mutants that survived: `to_uppercase` for `to_lowercase`, an empty own name claimed by a blank one, `Peer::muted`, `retired_at` and `short` read from elsewhere, the stored name cleaned (which breaks R2 and the log keeping the name as sent), the full key in `OwnKeyElsewhere`'s `Debug`, the prefix unpadded | Low | T01, T02, T04, T06, T10, T12, T13: the cases added |
| AE19 | R8 says the admission applies to any peer with no label; the code skips a retired one, which is already in the labelled budget | Nit | R8, R9: for an unknown peer or a new record, as R7 and the code; `is_unknown` made private |

## Spec 021 implemented

**2026-10-05 — The non-automatable acceptance criterion of spec 021-channel-session: a second reading of R9–R15 and R19 against `docs/spec.md` §4 steps 5–8 and "Messages from one's own key".** The human reviewer took Audit AD as that reading: pass B of round 1 walked R9 step 5 and R13–R19 against the code, and round 2 read R1–R33 afresh with the round-1 fixes and found no defect. The tests, clippy, `cargo deny` and the documentation lint are green on `mvp` (106986f), and `channel_decrypt` runs in the nightly fuzz workflow. Spec 021 is `implemented`; questions 025-R1 and 025-R2 stay open for spec 025-identity-regen.

## Audit AD

**2026-10-04 — Audit AD, the code audit of spec 021-channel-session (branches `021-a1` to `021-e`, PRs #19–#27), round 1 of three read-only passes (A: R1–R12, R18, R20, R21, R24, R26, R33; B: the own key and the `outbox`, R9 step 5, R13–R17, R19, R22, R23, R25, R31; C: code quality, tests, fuzz and property).** No blocker; no path found by which a server or a thief raises a false alarm while a signature is kept, shortens a signature's retention, removes the pending `key_retired`, or leaves memory and disk out of step. The human reviewer took every recommendation of the four decisions (AD1–AD4).

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AD1 | 016 R10 forbade randomness in a target, while the `MemoryStore` that 021 R29 requires draws sealing nonces; the verdict never depends on them | Low | 016 R10 bounds what decides the verdict (decision) |
| AD2 | R9's step-5 removal for the key being retired was bounded only by "within reach"; T09 asked an old blob to remove nothing, and an old-key entry dropped as stale but stored by the server would echo as a "thief" | Medium | R9, R19: also not past one `ttl_ms + 360 000`, as R14; an AEAD that does not open is `RetiredKey`; T09 restated against `now` (decision) |
| AD3 | A stale message's type is never read (013 R12), so "every entry for a `key_retired`" cannot apply to a stale one; T19 passed only because it sealed at `2^64 − 1` | Low | R14, R19, T19: every entry only for a readable, not stale `key_retired` (decision) |
| AD4 | AGENTS 22 allowed `==` on public identifiers "as map keys or for ordering"; the code also looks them up linearly | Low | AGENTS 22: "as map keys, in lookups or for ordering" (decision) |
| AD5 | A stale foreign own-key blob committed the full state on every push even when nothing changed, and it leaves no seen record, so a server could make the device write without bound | Medium | R14: a stale own-key blob that changes nothing commits nothing; test of 19 repeated pushes |
| AD6 | A rejected push could commit a waiting `synced_at` (R3 says only the cursor) | Low | `decrypt` commits only when the cursor's minute changed; test |
| AD7 | A backlog sample could turn a live sample's `clock_off` into its own and clear it later (R25) | Low | Only a live sample changes a live sample's flag |
| AD8 | `check_own_key` turned a libsodium failure in `verify` into `false` | Low | `Internal` passes through |
| AD9 | Tests that a mutant survived: `max_counter`, the cursor's `max`, `storage_full`, a plain `RetiredKey`, the `truncated_at` clamp in the gaps, R5's other `channel_id`, R7's headroom order, R17's same key, R22's edge, the thief's far-future and counter bounds, a `key_retired` below its entries, the pending cursor in `check_own_key`, the R15 echo after a regeneration, the R14 verdicts, the `clock_off` margins, and the R30 failure that never had to fire | Medium | Each clause tested; the property asserts that its one failure fired |
| AD10 | Duplications: the acceptance window in seven places, R11's listed time in `acked`, `acked` cloning a 64 KiB blob, the headroom constant redeclared in the tests, helpers copied across seven test files | Low | `accept_window`, `listed_time` shared, fields copied, the real `HEADROOM` and `RESERVE` pinned, helpers in `channel/tests.rs` |
| AD11 | The no-logger step matched only `log` and `tracing*` | Low | It also matches `slog*`, `env_logger`, `log4rs` and `fern` |

**Round 2.** Two passes: a fresh reading of R1–R33 with the round-1 fixes, which found them correct and no new defect; and 133 hand mutants of `session/`, 100 killed, 7 equivalent or untestable, 26 test gaps and no production defect.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AD12 | `MemoryStore::commits()` does not count a commit that changes nothing, so every "commits nothing" assertion let an empty commit through, AD5's own test included | Medium | Those assertions count every commit (`all_commits`) |
| AD13 | 26 mutants survived: the retiring key's own copy, a retired peer or the current key's entries treated as a thief's; `acked` on the `key_retired`; `max_counter` equality; the display-expiry edge; an unknown's `key_retired`; names and `last_seen`; peers-changed fields; the truncation window's edges; a compaction at a record's `purge_at`; and more | Medium | One test per gap (`channel/tests/edges.rs`); the five security-relevant mutants re-run and killed |
| AD14 | The echo of a superseded `key_retired` copy reads as a thief's and reports delivered old-key entries as not delivered; `under_retired_key` stands for "the same key" across two regenerations | Low | Open questions 025-R2 and 025-R1, decided with spec 025; T09 pins today's behaviour |
| AD15 | `for_fuzzing` took the seed by value against the Interface | Nit | By reference, as the Interface says |

Left as they are: the linear scans of the log per push (about 0.5–1 ms at a full 64 MiB log; an index only if spec 028's budget asks for it); `Received`, `Gap` and `Sender` derive a `Debug` that prints a whole `pk` (the core writes no log; clients must not log them); the Consequences of ADR 0029 and 0034 say a retired key's kept signatures are dropped at regeneration, while 021 R15 and §4 keep them until their purge (the specs govern; the ADRs are history); a stale pending `key_retired` is handed out unchanged until spec 025 brings its re-seal.

## Audit AC

**2026-10-04 — Audit AC, a subtraction audit of the state layer before spec 021-channel-session is implemented.** Sixteen audits had added rules to specs 020–028 and removed none. Read-only passes looked for rules that cost more than they protect: store failure, the own echo and the `sent_at` windows (name comparison is Audit AB). The human reviewer took every recommendation. Each change removes a rule; none adds a defence.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AC1 | On a store error other than `LogFull`, the channel held the own-key alert, the counter bump, `read_only` and the overtaken counters in memory and carried them to the reopened instance (`HeldOwnKey`), and `outbox` handed out entries and a `key_retired` re-sealed in memory for 600 000 ms. A failing disk is not an adversary of the threat model, and the alert's remedy, `regenerate_identity`, needs a commit anyway | Low | The channel is frozen until the probe of spec 027 R12: no `decrypt`, `check_own_key`, publish or commit; the push is fetched again after it. 021 R3, R13, R19, R20, R22, R23, Security; 025 R1, R4, R5; 027 R12, R14; 028 R10, R12, R14 |
| AC2 | R19's `LogFull` fallback and spec 025 R1's retry-once guarded a commit that cannot meet `LogFull`: while R18's check fails nothing but the reserve's commits appends, at most three records per `outbox` entry, and `Store::commit` refuses before writing (spec 020) | Low | The bound stated in R18 and tested in T19; a `LogFull` there is `Error::Internal` |
| AC3 | The last compaction time, carried over a reopen, only moved the first retry after a failed compaction from the 60 000 ms probe to 600 000 ms | Low | `last_compaction` and `set_last_compaction` removed; 021 R18, Security; 027 R14, R15 |
| AC4 | 021 R18 restated spec 020 R11 | Low | Cited |
| AC5 | An echo acknowledged an `outbox` entry whose `ack` was lost, or upgraded one already reported not delivered, under five conditions. That is delivery bookkeeping, not security, and the republish under the same `client_ref` (spec 030) already recovers a lost `ack` | Low | An echo is only `Replay`. 021 R3, R13, Security, T13; 028 R11, T11; `docs/spec.md` §4. Lost: one republished copy per lost `ack`, and an entry gone stale before the reconnect reads not delivered |
| AC6 | Kept signatures were filtered by the `epoch` they were sealed under. That filter protects nothing: the echo of a retired key stops at step 5 first, and no blob of another key can carry a signature equal to one of them | Low | Every kept signature is compared, including those of `under_retired_key` entries. The record's `epoch` and `client_ref` (spec 020) are written but no longer read, until the next `store_version`. 021 R13, R15, R19, Security; 025 R3; `docs/spec.md` §4. The decisions of ADR 0029 and 0034 are unchanged, so no new ADR. The sentence in their Consequences saying these signatures are "dropped in the regeneration commit" now reads "never matched" |
| AC7 | The client measured a message's life against two clocks, the signed `sent_at` and the server's `received_at`. That made a blob acceptable in `[sent_at − T, sent_at + 2T]`, and from it came own-key acceptance to `2T`, kept signatures to `3T`, seen records to `2·ttl_ms + 360 000`, display expiry from a clamped `received_at`, and a second display check. About ten requirements and their tests in specs 021 and 023 existed only to carry the server's clock | Medium | ADR 0044: one window `[sent_at − T, sent_at + T]` judged by the local clock. Expiry is `min(sent_at, arrival) + ttl_ms`; `received_at` only orders and moves the cursor. 021 R10–R12, R14, R15, R17, R19, R24, R26, Security, T10, T14, T15, T17, T26; 023 R1, Security, T01; `docs/spec.md` §2–§4, §6; `docs/threat-model.md` gains the server-revival row. Spec 013's step 2 and its `received_at` reference stay with their frozen vectors as a redundant subset. Lost: a message delayed by `d` lives `ttl_ms − d` on its receivers |

## Audit AB: name comparison

**2026-10-04 — Audit AB, a subtraction audit of the state layer before spec 021 is implemented: four read-only agents looked for rules that can be removed without weakening security, one area each. This section is the name comparison of ADR 0036; the human reviewer approved the recommendation.** Names are not what authenticates a member: every unknown key is drawn grey, quoted, with the unknown mark and its own short identifier, and only the 12 words or the QR verify it (`docs/spec.md` §7). The look-alike pipeline added a warning on top of that mark at the cost of two Unicode crates on the impersonator's path, a fuzz target and three High findings of audit J. None of spec 022 was implemented, so the change is to text only.

| # | Finding | Change |
| --- | --- | --- |
| AB-N1 | `name_key` ran NFKC, a UTS #39 skeleton twice, lowercase and three folds through `unicode-normalization` and `unicode-security`, for a warning the unknown mark already carries | ADR 0043 supersedes 0036: lowercase with white space and `INVISIBLE` removed, standard library only; look-alikes a stated residual (022 R4, Security, T04 pins the residual pairs as non-colliding; `docs/spec.md` §3, §7, §9) |
| AB-N2 | `INVISIBLE` was tied to the Unicode version of a crate that is no longer a dependency, and pinned by a digest | The toolchain's `char::UNICODE_VERSION`, U+3164 and U+FFA0 listed directly since nothing normalises them, a range count and a version check (022 R5, T05) |
| AB-N3 | The planned amendments of specs 010 (R16, T25) and 016 (R2, R8, R9) and the `name_key` fuzz target existed only for the two crates | Dropped; a property test stays, since `name_key` reads a `&str` the fuzzed payload decoder produced (022 R16, T16; 016 R2) |
| AB-N4 | Without look-alike collisions, a label field filled from the suggested name would let the impersonator choose the bytes of the user's label | No label field is filled or completed from a suggested name (055 R15, T15) |
| AB-N5 | 054 R17 `name_collides` and 026 refer to the comparison by reference | No text change in 054; 026's related ADR is 0043 |

The `Unicode-3.0` licence stays in `deny.toml`: `unicode-ident`, through the proc macros of `zeroize_derive`, still needs it. The password rule of spec 011 R15 (`White_Space` as a separator) and the Cc rules are not name comparison and are unchanged.

## Reading of spec 020 R10–R15

**2026-10-03 — The second reading the acceptance criterion of spec 020-store-files asks for: that every interruption of a commit, a compaction or a recovery leaves the previous commit or the new one.** The human reviewer read R10–R15 and found them sound; two agents read them independently, one from the spec's text and one from the code, under a model where a crash keeps any subset of the unsynced directory operations, in any order.

| # | Finding | Change |
| --- | --- | --- |
| R1 | A first commit created `messages.log` and renamed `state.bin` with no directory sync between: a crash could keep the state and lose the log's name, leaving `Corrupt` (both readings) | The directory synced after the header (R13) |
| R2 | A compaction did the same with `messages.log.new`, and a load's R14 rename followed by a second compaction could lose that rename under a state two generations ahead (both readings) | The directory synced after the new log (R15), which also makes R14's rename durable; R14 syncs after its rename |
| R3 | A destroy whose `channels/` sync failed still deleted, so a crash losing the rename brought the channel back half emptied, `Corrupt` (spec reading) | Nothing deleted until that sync succeeds (R21) |
| R4 | Text: a failed `fsync` stops the store only from the rename on; `F_FULLFSYNC` on Apple platforms, which `File::sync_all` already issues (confirmed in the disassembly); a compaction at generation `u32::MAX`; a commit with no load before it (both readings) | Security, R10, R15 |

With these, both readings conclude that every interruption leaves the previous commit, the new one, or `None` for a channel never committed. Spec 020 is `implemented`.

## Audit AA

**2026-10-01 — Audit AA, the code audit of the `store` crate of spec 020-store-files (branch `020-store`, slices (e1)–(g)), in rounds of three passes (A: structure and logic; B: the local CI and hand mutants; C: conformance with spec 020).**

**Round 1.** CI green; no defect in commit, load, compaction or recovery: every crash point and fault traced leaves the previous commit or the new one. 172 mutants, 98 killed; the survivors equivalent, far-fetched, or these:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AA1 | T11 checked the leftovers only after a `load` that deletes them itself, accepted a poisoning at any call, and stopped its fault loop at the first `Ok`, which a best-effort delete gives (AA1-A-1, AA1-A-2, AA1-B-5–AA1-B-7, AA1-C-1) | Medium | Each call's kind recorded under test: before the rename usable and clean, from it poisoned, a best-effort delete ignored and the commit standing |
| AA2 | The store tests failed about once in 40 runs: a helper child holds a copy of another test's lock between its fork and its exec (AA1-B-17) | Medium | The tests retry a `Locked` open for up to 2 s; 60 runs clean |
| AA3 | A first commit with records, which spec 021 never makes, would leave a channel `Corrupt` after a crash between its entries and its state (AA1-A, known gap) | Medium | Refused before any write (AA-Q1); R13, T13 |
| AA4 | No test of: a commit straight after a compaction, a log cut at an entry boundary, an entry's `len` raised, `remove` of a live store, the stores of a fast `DataDir` (which were not fast), a store keeping the lock after its `DataDir` is dropped, a foreign or unreadable directory surviving R19, the cleanup under the lock, a fault in a settings save, the syncs of each step, the crash points' places (AA1-B-1–AA1-B-4, AA1-B-8–AA1-B-15, AA1-C-2, AA1-C-3, AA1-C-5) | Medium | Tests for each; a fast `DataDir` hands out fast stores |
| AA5 | A log over 64 MiB was cut back instead of `Corrupt`; an `Io` was not shown to carry no path; `compact` could fail after its renames (AA1-C-4, AA1-C-6, AA1-A-5) | Low | `Corrupt` before any truncation; T26 in `store`; the count taken before the writes |
| AA6 | `check_store_io.sh` passed a grouped `use std::{fs, …}` and its self-test never ran the whole script (AA1-B-16) | Low | `std::{` refused; the self-test runs the script; R23 |
| AA7 | The golden files were not marked binary; T21 never faulted the final delete; a leftover `settings.bin.tmp` was never deleted; dead test lines (AA1-A-3, AA1-A-4, AA1-A-6–AA1-A-8, AA1-C-12) | Low | `.gitattributes`; T21 to k = 5; deleted at open (AA-Q2); removed |
| AA8 | Text: §10 had no phase 2 CI line, CONTRIBUTING no golden check, spec 001 no word of later jobs; R15 and R16 against what reading the log does and what `log_len` returns before a load; the test directory's name (AA1-C-7–AA1-C-10) | Low | Rewritten |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AA-Q1 | A first commit that carries records (AA1-A Q1) | Refuse it with `Corrupt` | R13, T13 |
| AA-Q2 | A leftover `settings.bin.tmp` (AA1-A Q2) | Deleted at `DataDir::open` | R22, T22 |

**Round 2.** CI green; 116 mutants, 81 killed, 0 failures in 100 runs of the store tests; the survivors equivalent, far-fetched, or these:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AA9 | `MemoryStore` took the first commit with records the real store refuses, so a spec 021 bug would pass every test in memory and fail on disk (AA2-C-1) | Medium | Refused there too; T13 for `MemoryStore`, the trait's `# Errors`; the tests seed with a record-free commit |
| AA10 | `check_store_io.sh` passed `use std::io::{stdout, Write}` and `std::io::prelude`, a path with no source, and its self-run passed whenever the child failed for any reason, such as a wrong `$0` (AA2-A-1, AA2-B-4–AA2-B-6) | Low | Both refused; no source fails; the self-run by absolute path, judged by its message; R23 |
| AA11 | The `Path` methods that reach the disk (`exists`, `is_dir`, `read_dir`, …), `remove_dir_all`, `create_dir` and `fs::metadata` passed both the script and clippy outside `fs.rs` (AA2-B-7) | Low | Ten more entries in `clippy.toml`; spec 010 R17, T26 |
| AA12 | Untested: a log that cannot be read surviving R19, the sync of a recovery's rename, a log of exactly 64 MiB; a dead branch in T22; the fast `DataDir` absent from the spec's body (AA2-B-1–AA2-B-3, AA2-A-2, AA2-C-2) | Low | Tests; removed; the Fast mode bullet |

**Round 3.** CI green; 77 mutants, 0 failures in 50 runs; no defect in the store's behaviour or its tests. The deny-lists were still short:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AA13 | Each round found another name past `check_store_io.sh` (`std::io::{…}`, `io::Write::write_all`, `std::os`), and its self-test judged the child by its message alone, so a script that reported but never failed passed (AA3-A-1, AA3-B-1, AA3-B-4) | Low | An allow-list: outside `fs.rs` only the modules of `std` that make no system call (AA-Q3); the self-test asks for a failure and its message, on an offending tree and on an empty one |
| AA14 | `clippy.toml`, `core`'s only I/O guard, lacked `Path::is_symlink`, `symlink_metadata`, `read_link`, `std::fs::exists`, `copy`, `remove_dir`, `std::process::Command::new`, `std::env::var_os` and others, and a path clippy cannot resolve is only a warning (AA3-C-1, AA3-B-2, AA3-B-3) | Low | Fourteen more entries, spec 010 R17 and T26; a CI step fails on clippy's "does not refer to" |
| AA15 | `DataDir::open` of a relative path whose every part is missing tried to create `""` and failed with `Io` (AA3-A-2) | Low | The empty ancestor is the current directory; a test |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AA-Q3 | Keep chasing banned names, or list what the store may name (AA3-A Q1) | The allow-list | 020 R23 |

Closed after round 3: the store's behaviour had no defect in any round, and what the last round found was breadth in two lists, now replaced by an allow-list.

Not changed: F13, a state file between the settings limit and its own, which `core::testing` cannot build (a state that large needs the builders of spec 021); a host that spawns processes can see the brief `Locked` of AA2 too, which `Device` (spec 027) will meet with a retry or not at all.

## Audit Z

**2026-10-01 — Audit Z, the first code audit of phase 0 (branch `phase0-audit` from `mvp` at 2136de2): specs 000–003 and what implements them — the CI workflows, `doc_lint`, `check_requirements`, `deny.toml`, the workspace lints and toolchain — in rounds of three passes (A: structure and logic; B: the local CI, 131 mutants and crafted git histories against `adr-guard` and `commit-lint`; C: conformance with the specs, AGENTS and `docs/spec.md`).** Audits A–D had reviewed documents, not this code.

**Round 1.** CI green; the guards had holes:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AZ1 | `adr-guard` and `commit-lint` run on pull requests only, and every merge reached `mvp` by a local push, so neither ever ran; `mvp` had no protection (Z1-A-1, Z1-C-2) | High | Branch protection on `mvp`: a pull request with the jobs green (AZ-Q1, AZ-Q5); 001 R10 |
| AZ2 | `adr-guard` missed the module roots `crypto.rs` and `proto.rs`, where most derivations live, a file renamed out of a protected path, and the tags and derivations of specs 020 and 031 (Z1-A-2–Z1-A-4, Z1-B-1, Z1-B-2, Z1-C-1) | High | `(proto|crypto|storage)(/|\.rs$)`, specs 020 and 031, `--no-renames` (AZ-Q3); 001 R8, §10 |
| AZ3 | Neither Python guard tested itself: removing most rules left CI green (3 of 55 `doc_lint` mutants and 3 of 22 `check_requirements` mutants killed); `doc_lint` missed a duplicate ADR number, a misnamed ADR file and a requirement after a `###` subheading (Z1-A-7, Z1-B-6–Z1-B-8) | Medium | `doc_lint_selftest.py` (003 R8) and a self-test in `check_requirements` (001 R7); the three rules |
| AZ4 | The spec 000 tests matched text anywhere, so a commented-out line passed; no check that each crate takes the workspace lints, of the release profile, the edition, the exact URL, the wrappers, licences and source rules of `deny.toml`, or of `.gitignore` beyond `inici` (Z1-A-9, Z1-B-3–Z1-B-5, Z1-C-7, Z1-C-9) | Medium | Each line read in its TOML section; T03–T08 |
| AZ5 | `tempfile` unbanned, so the OS randomness it pulls could reach a shipped crate; `commit-lint` passed an empty subject and an unreachable base; no `pipefail` (Z1-A-6, Z1-A-8, Z1-B-9) | Medium | `tempfile` and `rusty-fork` only under `proptest`; `defaults: shell: bash`; the subjects read on their own line |
| AZ6 | Specs 027, 040 and 053 required amendments at their acceptance that were not made: AGENTS 20 described four handles where ADR 0037 has one, §5 an old trigger (Z1-C-3) | Medium | AGENTS 20 and 23 and §5 now, with `check_s027_t22_r22_boundary_documented`; the rest moved to each spec's implementation (AZ-Q2) |
| AZ7 | Stale text: §11 without `fuzz.yml`, `crates/host/` and `clippy.toml`; 000 R1 and R8, AGENTS 10, 002 R4 and its count of ADRs and title limit, 001's `@v4` and "eight jobs"; the landing workflow not run on the docs it builds from; `.claude/worktrees/` not ignored (Z1-A-10, Z1-C-4–Z1-C-6, Z1-C-8, Z1-C-10) | Low | Rewritten |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AZ-Q1 | Pull requests and branch protection, or the checks on every push (Z1-A Q1, Z1-C Q1) | Protect `mvp`; every change by pull request | 001 R10; the repository's settings |
| AZ-Q2 | The amendments 027, 040 and 053 owed at acceptance (Z1-C Q2) | AGENTS 20, 23 and §5 now; the rest at implementation | 027 R22, 040 R14, 053 R20 |
| AZ-Q3 | Widen `adr-guard` to 020, 031 and `storage`, and `docs/spec.md` too (Z1-A Q2) | 020, 031, `storage` and the module roots; not `docs/spec.md` | 001 R8 |
| AZ-Q4 | `SECURITY.md` points to private vulnerability reporting, switched off (Z1-A-5) | The reviewer turns it on | — |
| AZ-Q5 | A required approval cannot be given by the one account that opens the pull request | The pull request and its jobs are required; the reviewer's merge is the review | — |

**Round 2.** CI green; 199 mutants, 115 killed, every survivor equivalent, far-fetched or outside phase 0 but these:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AZ8 | The round-1 step `s000_t05_r05_inici_is_ignored` gave `git check-ignore -q` eight paths, which it refuses: the doc-lint job failed on every run, and the local CI list does not run it (Z2-A-1, Z2-B-1) | High | One path at a time |
| AZ9 | A renamed ADR counted as the new ADR `adr-guard` asks for, since round 1 diffed with `--no-renames` (Z2-A-2) | Medium | A new ADR is a file whose number the base does not have |
| AZ10 | `doc_lint_selftest` checked only that the lint failed, so another rule failing hid a dead one: the ADR state fixture broke line 3 instead of the vocabulary, and contiguous numbering, the index state, §10 listing every spec, the spec state, phase and index rows, four R6 paths and spec 027 R22 had no fixture (Z2-A-3, Z2-B-2, Z2-B-3) | Medium | Each fixture names its rule's message; 28 fixtures; 003 R8 |
| AZ11 | The `check_requirements` fixtures had no two-digit requirement and none under a `###` subheading (Z2-A-3) | Low | R10 under `### Notes`, and a test of R100 that must not cover it |
| AZ12 | T08 left `sodiumoxide` out, read a ban from any `{ crate =` line, `skip` too, and the licence and source sections by containment; `section()` read past a `[[array]]` (Z2-A-4, Z2-A-5, Z2-B-4) | Low | `sodiumoxide`; bans from `deny = [ … ]`; both sections compared whole; `[[` closes a section |
| AZ13 | §9 said `cargo deny` checks the core does no I/O; §10 named only 011–017 for `adr-not-needed`; 000's tree lacked `clippy.toml` and the self-test; the `Updated` date of `docs/spec.md` was stale since audit Y, which no pull request had checked (Z2-A-6) | Low | Rewritten |

**Round 3.** CI green; 85 crafted histories and 251 mutants, every survivor equivalent, far-fetched or caught by another step but these:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AZ14 | Adding the `adr-not-needed` label started no run, and a rerun reads the old payload, so the label could never turn `adr-guard` green (Z3-A-1) | Medium | The workflow also runs on `labeled` and `unlabeled` |
| AZ15 | The file framing of spec 020 goes into `crates/store/src/`, which `adr-guard` did not protect (Z3 question 1) | Medium | Protected (AZ-Q6); 001 R8, §10 |
| AZ16 | Dropping `specs/`, `.claude/` or `AGENTS.md` from the exclusions of `check_requirements` left it green: every spec's own `T` lines would cover it (Z3-A-2) | Medium | The fixture names the tests in its spec, `.claude/` and `AGENTS.md` too |
| AZ17 | T08 took `deny-multiple-versions`, which lifts an outright ban, a `[[licenses.exceptions]]` table and `[sources.allow-org]` (Z3-B-1) | Low | An outright ban has no key but `reason`; the list of tables is exact |
| AZ18 | R6 read the date of the test merge GitHub makes, and had no case that must pass; §3 titles, an index row with no file, `superseded by` with a bad number, `e.g.` and `such as`, and the spec id in AGENTS 20 had no fixture; the §9 rule read to the end of the file (Z3-A-3–Z3-A-5, Z3-B-2–Z3-B-4) | Low | `--no-merges`; 34 fixtures, three that must pass; §9 ends at §10 |
| AZ19 | The local CI list did not run the two layout steps, which is how AZ8 went unseen; §10 named phase 2 where only 020 and 031 are protected; the pull request template's count of commits (Z3-C-2) | Low | `scripts/check_layout.sh`, run by both; rewritten |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AZ-Q6 | Protect `crates/store/src/`, or move the file framing into `core::storage` | Protect `crates/store/src/` | 001 R8 |

**Round 4.** CI green; 103 crafted histories and 209 mutants, every survivor equivalent, far-fetched or caught by another step but these, after which the audit closed with nothing substantive left:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AZ20 | A pull request retargeted to `mvp` fires only `edited`, so its check from the old base stayed green (Z4-A-1) | Medium | `edited` among the triggers; 001 R10 |
| AZ21 | The frozen files of spec 020 R31, `crates/store/tests/golden/`, are the store format and were not protected (Z4-A-2) | Medium | Protected; 001 R8, §10 |
| AZ22 | T08 did not read `[graph]` or `[advisories]`, where `exclude` takes a banned crate out of every check (Z4-A-4, Z4-B-1) | Low | Both sections compared whole |
| AZ23 | No fixture pinned `--no-merges`, the end of §9, a §3 row with no file, a §3 state, "For example", or an untouched spec under an old header (Z4-A-3, Z4-B-2, Z4-B-3) | Low | 38 fixtures; a branch resolving a docs/spec.md conflict in its own merge dates the header by a later commit that is not a merge |
| AZ24 | §10 left out 027, whose exit test lives under the protected `crates/store/src/`; the template's command list lacked the layout script (Z4-C-1, Z4-C-2) | Low | Rewritten |

The `labeled`, `unlabeled` and `edited` triggers stay a review item (001 T10) (Z4-B-4).

## Audit Y

**2026-10-01 — Audit Y, a re-audit of phase 1 in rounds (branch `phase1-audit` from `mvp` at 107c578), after audits Q–W had run one round each.** Each round runs three passes (A: structure, simplicity and logic; B: the local CI run and hand mutants; C: conformance) over three groups (G1: specs 010, 015 and `core::Error`; G2: specs 011, 014, 017; G3: specs 012, 013, 016), nine agents in all. The human reviewer allowed specs to change, nothing being in production.

**Round 1.** CI green in every group; 569 mutants (159 in G1, 201 in G2, 209 in G3), 77 survivors, about half of them equivalent. No defect in code that ships but one test that did not test what it claimed. Findings (numbered AY) and changes:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AY1 | Four of the five "strict" Ed25519 negatives of `010.json` were rejected by any verifier, so strictness, on which the server relies, was proved by `signature_s_plus_l` alone; three names said the wrong thing about their points (Y1-G1A-1, Y1-G1C-1) | Medium | ADR 0042: the twelve ed25519-speccheck cases, three renames (AY-Q1) |
| AY2 | Unpinned guards and comparisons: the public types' `PartialEq`, the FFI size checks against a buffer one byte too large, `memzero`, the base64 buffer guard, the password limits at the wrapper, a short AEAD ciphertext, the second half of `random_bytes`, `Secret`'s traits outside `secret.rs`, two of the three forbidden features, `BadEncoding` in the mapping test, the loader's tab and non-object inputs (Y1-G1A-4, Y1-G1A-5, Y1-G1B-1–Y1-G1B-8, Y1-G1C-2, Y1-G1C-3) | Medium | The tests |
| AY3 | `Secret::random` left an unwiped copy of a fresh key (R18); `clippy.toml` banned a handful of I/O and clock calls of many (Y1-G1A-2, Y1-G1A-6, Y1-G1C-5) | Low | Drawn into its own storage; twelve more methods banned (010 R17) |
| AY4 | `unpad` and T21 claimed a multiple-of-block check libsodium does not make; `pad`'s bound, `version()`, the Interface, R14's "before any libsodium call", the loader's per-name rule (015 R1), the README's example, the lint allows of `lib.rs`, the skill's examples (Y1-G1A-3, Y1-G1A-7, Y1-G1A-8, Y1-G1C-4, Y1-G1C-6–Y1-G1C-8, Y1-G2A-3, Y1-G3A-3) | Low | Specs 010 and 015, comments, tests |
| AY5 | `Config::host` parsed the URL again at each call with an empty fallback, the string the subscription signature covers (Y1-G2A-1) | Low | Parsed once at construction |
| AY6 | Untested in G2: `Fingerprint`'s redacted `Debug`, a writer that grows to its capacity by doubling, a 57-character onion label, U+001C..=U+001F and non-ASCII capitals in the canonical password (Rust and the script), `config_version` 0 with key 8, the password negatives refused by the canonical form; the pinned `.chatcfg` header unchecked by the script; R22 and §9 wording (Y1-G2A-2, Y1-G2B-1–Y1-G2B-5, Y1-G2C-1–Y1-G2C-3) | Low | Tests, two `require`s, specs 011 and `docs/spec.md` §9 |
| AY7 | `Payload::decode`, which skips the stale check, was compiled into the product; the script's and seed script's `unpad` looser than libsodium's; T17 without `sent_at = 2^64 − 1` against the other times; the policy byte, `payload_decode`'s lack of validation, five impure words and the seed counts unpinned; three 013 vectors and the margin not guarded by the script (Y1-G3A-1, Y1-G3A-2, Y1-G3B-1–Y1-G3B-6, Y1-G3C-3) | Low | `cfg(any(test, fuzzing))`, the tests, the guards, `SEED_COUNTS` |
| AY8 | Wording: 016 T05 and R5, 013 R17 and its table without "at times that pass step 2", 016 R2's list of amending specs, §4's `enc_hdr` notation, AGENTS 21 asking a round trip of each fuzz entry against spec 016 (Y1-G3C-1, Y1-G3C-2, Y1-G3C-4–Y1-G3C-6) | Low | Rewritten (AY-Q2) |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AY-Q1 | May the frozen `010.json` change to prove strictness (Y1-G1A Q1, Y1-G1C Q1) | Yes, by an ADR: it describes no format | ADR 0042, AGENTS 18 |
| AY-Q2 | AGENTS 21 against spec 016 on round trips of fuzz entries (Y1-G3C-6) | AGENTS 21 asks the round trip of the codecs only | AGENTS 21 |

**Round 2**, six agents (passes A and C together per group; pass B per group), over the round-1 fixes and the rest: 425 mutants (98, 128, 199), every round-1 real gap dead. Three passes found nothing substantive; the others, test gaps and wording, closed:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AY9 | T26 checked 8 of the 20 methods of R17, by substring and with one "AGENTS 10" for the file (Y2-G1-1, Y2-G1B-1) | Medium | The exact list, a reason per entry |
| AY10 | The text claimed every speccheck case defeats a lax verifier; about half pin the cofactorless equation and `R`'s encoding instead; ADR 0042 named amendments not made and a platform test that does not read `010.json` (Y2-G1-2, Y2-G1-3) | Low | Spec 010 R10 and Security, T15, ADR 0042, `docs/spec.md` §3 and §4 |
| AY11 | Untested: the decrypt size checks one byte too small over a real seal, the second half and last byte of a random `Secret`, a path-qualified impl on `Secret`, the loader's CR, form feed, vertical tab, escapes and DEL/C1, `stream_xor` at 0 bytes and 1 MiB, the hash of nothing (Y2-G1B-2–Y2-G1B-6) | Low | The tests |
| AY12 | The canonical password's White_Space pinned at a few code points (Rust and script); the onion label's characters and suffix case; the channel check at its first and last byte (Y2-G2B-1, Y2-G2B-2, Y2-G2B-4) | Low | Every code point checked; the script's written-out table checked against `isspace`; three URLs; two QRs |
| AY13 | The host parsed twice, the second after the derivation; §6 described WHATWG's host, not the bytes `Config::host()` signs; R22's wording; the Interface's `Config` (Y2-G2-1, Y2-G2-3–Y2-G2-5) | Low | `check_ranges` returns the host; §6, 011 R22, Vectors and Interface |
| AY14 | `PayloadHead` visible to the whole crate; the `decode` gate unpinned; the free-function reach rule refused a module path, which 027 R17 would trip on; `std::io`, `net`, `process`, `thread`, `time` and `env` without a checker fixture; the TTL half of the margin unpinned; a misplaced docstring and three stale comments (Y2-G1-4–Y2-G1-6, Y2-G2-2, Y2-G3-1–Y2-G3-3, Y2-G3B-1–Y2-G3B-3) | Low | `pub(super)`, a source test, R6's rule, the fixtures, a `require`, the comments |

Not changed: `padded_record`'s capacity, whose growth no test can see (Y2-G2B-3); making `pad` refuse to grow would break the envelope, whose padded payload grows by one byte and holds no key.

**Round 3**, the same six agents (264 mutants: every round-2 real gap re-run, 118 new). The three passes A and C found nothing substantive; G3's mutants, nothing; G1's and G2's, test gaps only:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AY15 | No test refused a tag-only forgery of the empty plaintext, in the AEAD or the secret box; the last byte of a random `Secret` and of `random_bytes` pinned only together; a truncated 1 MiB keystream passed its round trip; the loader's trailing comma and `false` (Y3-G1B-1–Y3-G1B-5) | Low | The tests |
| AY16 | Untested in spec 011: a name of 33 two-byte characters at `create`, `proto_version` 0, a file version of 0, a key 6 of the wrong width (Y3-G2B-1–Y3-G2B-4) | Low | One test |
| AY17 | The reference script let DEL and the C1 controls through to a file the loader refuses; T15 of 011 did not say it checks every code point; a stale comment in the checker; this log's AY12 row (Y3-G1-1, Y3-G2-1, Y3-G2-2, Y3-G3) | Low | A `require`, the text |

**Round 4**, a confirmation round of passes B in G1 and G2, the other passes having found nothing in round 3 (69 mutants, every round-3 gap dead). Nothing substantive; the last test gaps closed:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AY18 | A suggested name tested at 5 of the 65 Cc code points; a capitalised scheme, a percent sign and `!` in a host untested; a duplicate key the loader would catch only when adjacent (Y4-G2B-1, Y4-G2B-2, Y4-G1B-1) | Low | Every Cc code point; five URLs in T05; one row |

Stopped after round 4: every pass of the last two rounds found nothing substantive, and what survives is equivalent or far-fetched.


## Audit X

**2026-09-30 — Audit X, code audit of the `core` half of spec 020-store-files (branch `020-store-files`, slices (a)–(d3), before the `store` crate), in three independent passes (X-A: structure and simplicity; X-B: the local CI run and 126 hand mutants of the storage code, the doubles and the reference-script section; X-C: conformance with spec 020, `docs/spec.md` §4, §8, §9 and the specs 020 amends, and the Limits recomputed from the schemas).** CI green; every schema matched the spec key by key and every limit recomputed to its constant; no defect in code that ships. 55 mutants survived, 9 of them equivalent; the tests below kill the rest. Findings (numbered AX) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AX1 | The round trips compared an encoding with its own re-encoding and never went through `seal` and `open`, so a symmetric swap (key 14 written from the other boolean) passed; `state_eq`'s own test changed 8 of its 16 fields (X-A1, X-A9, X-B4, X-C2, X-C7) | Medium | `open(seal(x))` compared with `state_eq`, `records_eq` and `settings_eq`; `state_reference` sets `own_key_used_elsewhere`; a change per field |
| AX2 | No test left out a mandatory key, planted a key of another log kind, checked a bound on open (names, config, list counts, body), a version other than 2, the derivation tags against fixed values, or `K_settings` against `K_db` (X-B1–X-B3, X-B5–X-B7) | Medium | A test per rule; known answers from Python's `hashlib.blake2b` |
| AX3 | `MemoryStore::commit` opened the whole log it appends to; `Faults` shared one counter between two faults; gaps in the doubles' tests (list wrapping, destroy, a failed commit, stale bytes, the exact log limit) (X-A2, X-A7, X-B8, X-B11, X-C11) | Medium | Commit reads the state and the committed length only; a counter per fault; the tests |
| AX4 | The `store` tests could not build a `Settings`, and the file limits `store` checks before reading lived only as crate-internal record maxima (X-C1, X-C9) | Medium | `testing::settings` and `settings_eq`; `MAX_STATE_FILE`, `MAX_SETTINGS_FILE`, `MAX_LOG_ENTRY` and `MAX_LOG_LEN` exported (AX-Q1, AX-Q2) |
| AX5 | Three `within` helpers, a `missing` closure per decoder, bare widths, enum bytes mapped inline, a 75-line encoder, `own` naming a `client_ref`, the state tests in the module file (X-A3–X-A5, X-A10–X-A14) | Low | One `within` and one `required`, named widths, `to_byte`/`from_byte`, `check_limits`, `own_client_ref`, `storage/state/tests.rs` |
| AX6 | Negative vectors that could break another rule and still say `Corrupt`; the list reader's check order and exact allocation untested (X-B9, X-B10, X-B12) | Low | Each negative is its positive plus its one edit; T01 cases |
| AX7 | Stale text: 011 R20 without `Store`, 016's Interface, exclusions and acceptance, the rust skill's feature sentence and `patterns.md` §3, `docs/spec.md` §8 and §9 on the old `Store` and `K_db` for `settings.bin`, two doc comments; a log test named after R8 (X-A6, X-A16, X-C3, X-C4, X-C8, X-C10) | Low | Rewritten; `s020_t09_r09_log_schema` |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AX-Q1 | How the `store` tests get settings (X-C Q1) | A builder and `settings_eq` in `core::testing` | Interface |
| AX-Q2 | Where the file limits live (X-C Q2) | All four exported by `core` | Interface |
| AX-Q3 | Which byte an entry's `offset` names (X-C Q3) | That of its `len`, 9 for the first | R5, R9 |
| AX-Q4 | Fuzz the nested-record reader, which no production schema uses yet (X-C Q4) | Yes: `record_decode` also drives the codec schema | 020 R29, 016 R3 |
| AX-Q5 | `duplicate` returning a `Result` for a copy that cannot fail (X-A Q1) | Return the state | Interface |
| AX-Q6 | Wipe a message's display name like its body (X-A Q2) | Yes | Interface |
| AX-Q7 | Constant time for the config inside `state_eq` (X-A Q3) | `==` in test code; the spec says so | Interface |

**Round 2**, the same three passes over the fixed code (185 mutants, the 126 of round 1 re-expressed and 59 new; 36 survived, 12 of them equivalent). Findings and changes:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AX8 | `MemoryStore::compact` took the generation from the state it was handed, which a channel keeps in memory unchanged, so two compactions in one session would repeat a generation, what R15 and ADR 0035 exist to prevent; R15 did not say whose generation; nothing committed after a compaction or compacted twice (X2-A2, X2-C1, X2-B2) | Medium | The store's own generation (AX-Q8); `log_position`'s doc; a test of two compactions from one stale state |
| AX9 | No test tied a field of a peer, `outbox` entry, old key or `acked` record to its key, so a swap made alike in encoder and decoder passed (X2-A1) | Medium | Records built by hand with a distinct value per key |
| AX10 | The exported file limits and the record maxima were never pinned by value; the per-fault counters, the settings builder and comparison, two load checks and `duplicate`'s log position untested; the long-blob case broke the framing instead of the bound; two codec negatives not pinned to their edit (X2-B1, X2-B3–X2-B8) | Low | The tests; the case planted at key 3 |
| AX11 | `record_decode` had no seed with a real `bool`, nested record or list (X2-C6) | Low | Seeded from the `types` vectors of `020.json` too (016 R8) |
| AX12 | Stale text: `patterns.md` §5 and the architecture skill with the old `WriteBatch`, 027's list of `pub` items without the file limits, `docs/spec.md` on `store` and on who adds the codec types, 017's test-schema paragraph, the fuzz script's comment, 020's file table; 027 R17's wider reach check would flag the item decoders passed by path (X2-C2–X2-C5, X2-C7) | Low | Rewritten; 027 R17 excludes the three item decoders |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AX-Q8 | Where a compaction takes its generation (X2-A Q1) | From the store, the `state.bin` it last loaded or wrote | R15 |
| AX-Q9 | Wipe the names the state holds, after AX-Q6 (X2-A Q2) | A peer's last display name only, the data the log wipes; labels and local names stay plain | Interface |
| AX-Q10 | AGENTS 23 on the old `commit(WriteBatch)` and a count that skipped only the cursor (X2-C Q1) | Reworded: `commit(&WriteBatch)`, and `commits` skips a commit that moves only the cursor or `synced_at` | AGENTS 23 |

**Round 3**, the same three passes (235 mutants: round 2's re-run, 50 new). Passes A and C found nothing substantive; B found test gaps only, no defect in shipped code. Changes:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AX13 | The proxy's host grammar was untested (an empty host, uppercase, `_`, port 65536, `+9050`, an onion host); the round-2 counter test re-armed a fault and so hid a shared counter; a never-committed compaction, `log_len` over stale bytes, `Vault::remove` and `fail_compactions` against `destroy` untested (X3-B1–X3-B4) | Low | The tests |
| AX14 | `fuzz_seeds.py` checked itself against its own table, so a lost row or a wrong schema passed (X3-B5) | Low | Its rows checked against R2's list, each decoder against its schemas, the `ignore` byte against `fuzz_entry.rs` |
| AX15 | The `store` crate's T15 did not ask for two compactions from one stale state; `ChannelFiles` did not say it keeps its log position; `WriteBatch` had no way to give its parts back after `Ok` (021 R2); 027 R17 named three of the five decoders its wider check would flag; the commit count "other than the cursor" left in §10, the PR and spec templates and the rust skill, `commit(Batch)` in §12, `StoreError::TooLarge` in the skill (X3-C1–X3-C4) | Low | T15, the Interface and `WriteBatch::into_parts`, 027 R17's rule, the wording |
| AX16 | The doubles do not model the live-store lock of R20 (X3-A Q1) | Low | The Interface says so; T20 checks it over the real store |

**Round 4**, passes B and C only, A having found nothing in round 3 (83 mutants: round 3's gaps re-run, all dead, and 48 new). Both found nothing substantive: small test gaps and text left behind, closed.

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AX17 | `into_parts` tested with one record; the memory log never planted by hand, so a layout changed alike in `append` and `entries` passed; a committed length inside the header, a generation-0 header with a byte after it and no state, and a bad list item ahead of a framing error untested (X4-B1–X4-B5) | Low | The tests |
| AX18 | The vectors README kept the old commit count; the encrypt sketch of `patterns.md` dropped the records `into_parts` hands back (021 R2, R8); `fuzz_seeds.py`'s check read the files from the table it checks; History lines missing in 020 and 027 (X4-C1–X4-C4) | Low | Rewritten; the check names each decoder's files |

Stopped after round 4: every pass of the last round found nothing substantive; the survivors left are equivalent or weaken a checker's own guard.

Not changed: the equivalent mutants (the size check before the box, which `secretbox_open` repeats; the record bound no valid state reaches; the vector values a test does not single out). Slices (b1), (b2) and (c) are above 400 net lines, with their reason in the commits; (c) is to be split between log and settings when it goes to a pull request. `020.json` is a new file: its pull request needs the reviewer's `adr-not-needed` label or an ADR, since `adr-guard` refuses any diff under `specs/vectors/` without one (AGENTS 18).

## Phase 1 closed

**2026-09-29 — Phase 1 (crypto core) closed on `mvp`.** Specs 010–017 are `implemented`. The exit criteria of `docs/spec.md` §10 hold: `cargo test` reproduces every vector the reference script of spec 015 writes for specs 011–014 and 017, the mutation table of spec 013 and its property included; each of the seven fuzz targets of spec 016 ran one hour with no crash in the nightly workflow (run 36580474551). The internal review of `proto` by a second person was dropped from the criteria by the reviewer (audit W, AW-Q1). From this commit the vectors of `specs/vectors/` are frozen (AGENTS 18): a vector changes only with a new `proto_version` and an ADR, and the `adr-not-needed` label no longer covers a vector change.

## Audit W

**2026-09-29 — Audit W, code audit of spec 016-fuzz-harness (branch `016-fuzz-harness`, slices (a) and (b)), in three independent passes (W-A: structure and simplicity; W-B: the local CI run, 42 mutants of `fuzz_entry`, 42 of the checker and 27 of the seed script; W-C: conformance with spec 016, `docs/spec.md` §10 and §11, specs 001, 011, 013–015, 017 and the specs that add targets).** CI green; no defect in the code that ships. The seven targets ran 15 minutes each on the dated nightly with no crash, 9 to 500 million runs per target. Findings (numbered AW) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AW1 | The tests of `receive` and `receive_signed` sealed with the entries' own `context()`, so a wrong channel or TTL passed; T05 let `BadPayload` through, so the truncation and padding of R5 were untested; four entries had no verdict test and `QR_CHANNEL` was tied to nothing (W-A1, WA2, W-B R07–R29, W-C WC6) | Medium | A context built in the tests, the expiry bound, T05 asserts `Ok` or `Expired` and pins the counter, the sender, 63 blocks, the bytes after them and the padding; `receive_signed_verdict` returns `Opened`; `s016_t08_r08_seeds_reach_their_entries` |
| AW2 | The checker missed parsers with a lifetime or generics, took two functions of one name for one, never flagged a stale exclusion, let any code beside the target macro through, missed grouped imports and the randomness of `core`, read untracked files, and had fixtures for T06 only (W-A3–WA7, W-B C03–C39, W-C WC2, WC3, WC5) | Medium | R6 reaches a method as `T::name(`, exclusions are `T::name` and must name a function; T07 compares each target with the template and each entry with its one call; wider T10; `git ls-files`; a fixture for every rule, run each time |
| AW3 | `fuzz_seeds.py` deleted the grown corpus, wrote each filter twice, and its check compared file names only (W-A8, WA9, W-B S01–S26) | Medium | Seeds are written beside the corpus; one table; the check cuts each seed by its layout and compares the vector's fields |
| AW4 | The nightly installed `cargo-fuzz` under the pinned stable it never installed, kept no crashing input and flagged a slow input only after 20 minutes (W-A10, WA11, W-C WC1, W-B §4) | Medium | `cargo +nightly install`, the artifacts kept on failure, `-timeout=10` (R9) |
| AW5 | Inconsistent splits, a helper named like the parsers, stale docs, a one-entry `.sh` list in §11 and the Interface, §10 without the steps of R12, AGENTS 8 silent on the fuzz crate (W-A12–WA16, W-C WC4, WC16, WC17) | Low | `fuzz_entry.rs`, spec 016's Interface, `docs/spec.md` §10 and §11, AGENTS 8 |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AW-Q1 | The phase 1 exit asked for an internal review of `proto` by a second person, recorded here by name (W-C D1) | Dropped: the reviewer will not do it; the independent audits S–W stand in its place | `docs/spec.md` §10; the acceptance criteria of specs 013, 016 and 017 |
| AW-Q2 | Keep the crashing input, pin `cargo-fuzz`, a limit per input (W-C D2, D3, W-A D3) | Keep the input and a limit of 10 s; `cargo-fuzz` unpinned | R9 and `fuzz.yml` |
| AW-Q3 | When 016 is `implemented` (W-C D4) | After the first green hour of all seven targets on GitHub | — |
| AW-Q4 | How strict "reached" is (W-A D1) | The technically correct rule | R6, spec 020 R29 |

Not changed: the equivalent mutants (the server URL of the context, which derives nothing; an AEAD failure after a correct seal; the checker's self-tests, whose removal is invisible by construction), the one PR for both slices (551 and 318 net lines, the first above 400 with its reason in the commit), and the seed check on every pull request, left to the nightly (W-C D6).

## Audit V

**2026-09-29 — Audit V, code audit of spec 014-fingerprint (branch `014-fingerprint`, one slice), in three independent passes (V-A: structure and simplicity; V-B: the local CI run, 63 mutants of the Rust code and 40 of the reference-script section; V-C: conformance with spec 014, `docs/spec.md` §4, §7, §9, ADR 0025, 0028, specs 010, 011, 015 and the specs that consume 014, and an independent recomputation of the 15 vectors).** CI green; no defect in the code. The reviewer read the first three words of `words_reference` against the list by hand (lines 1153, 1087 and 864: `mosquito`, `march`, `hip`), the acceptance criterion's non-automatable step. Findings (numbered AV) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AV1 | The derived `Debug` of `Fingerprint` printed the QR, which holds the whole `channel_id` and `pk_u`, against AGENTS 19 (V-A1) | Medium | A `Debug` by hand that shows `short` alone, T08 pins it; the reviewer kept `Clone`, `PartialEq` and `Eq` |
| AV2 | A prefix edited at a byte other than 8 passed, and nothing fixed that the prefix is checked before the channel (V-B #64, #51, V-A9) | Low | T04 edits each prefix byte, a malformed QR of another channel, a space; R4 states the order |
| AV3 | Vectors that could lose their point with every test green: `words_reference` from another fingerprint, too few indices, `qr_reference` of another key, a negative grown to 75 bytes, the bits after 132 cleared (V-B #17–#34) | Low | The checkers pin the reference key and fingerprint and the 12 indices; the script requires each edit's shape |
| AV4 | The bit extraction took five error sites where three suffice; `QR_LEN`, the prefix length and the mask were bare; shared doc comments; a rustdoc link to a private item; T05 retyped three vectors (V-A2–VA8, VA10–VA12) | Low | Simpler `words`, derived constants, docs, T05 keeps what no vector covers; script style |
| AV5 | R3 and R4 named spec 011's decoder, R7 called the fifth negative an edit, the Interface omitted the derives, the re-export and the uniffi mirror, T01, T03, T05 and T08 said "on the vector" for what the dispatch checks, and 014 and 040 R14 said `qr_other_channel` uses another channel (V-C1–VC12) | Low | Specs 014 and 040; the vector's origin; 055 R18 cites `docs/spec.md` §4 for the rule that all 12 words must match, which 014 never held |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AV-Q1 | May the public `Fingerprint` be cloned, compared and printed, and be public from `core` now? (V-C D1, D2) | Yes, with a `Debug` that shows the 4 words only (AV1) | Interface of spec 014 |
| AV-Q2 | Correct the text on which channel `qr_other_channel` uses, and its origin in `014.json` (V-C D3) | Correct | Specs 014 and 040, `014.json` |
| AV-Q3 | One slice of 488 net lines against the 400 of AGENTS 14 (V-A13, V-C14) | Accept, most of it is tests | History of spec 014 |

Not changed: the equivalent mutants — the length check (a QR of any other length fails the decoded length), the unreachable split and word-lookup errors, `ct_eq` against `!=` (constant time cannot be seen by a test; review holds R4's `ct_eq` on the prefix), and script inputs replaced by other valid ones. `WORD_COUNT` keeps the name the Interface gives it, though `wordlist::WORD_COUNT` means 2 048 (V-A5); `#[non_exhaustive]` on `Fingerprint` is left to spec 027-core-api, since the bindings have their own mirror (V-A decision 2).

## Audit U

**2026-09-29 — Audit U, code audit of spec 013-wire-message (branch `013-wire-message`, slices (a)–(c)), in three independent passes (U-A: structure and simplicity; U-B: the local CI run, 81 mutants of the Rust code and 30 of the reference-script section; U-C: conformance with spec 013, `docs/spec.md` §4, ADR 0005, 0018, 0023, 0027, 0029, 0030, 0032, 0033, and an independent checker of the 29 vectors).** CI green; no defect in the code. U-C is the second reading the acceptance criterion asks for: the offsets of R1 and the order of R11 and R12 match `docs/spec.md` §4 byte for byte, and every vector has the outcome its row gives. Findings (numbered AU) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AU1 | Boundaries no test reached: a blob of 161 bytes (k = 0), a divisor of 60 000 other than 60 000, a Cc character outside ASCII, a name limit counted in characters, the name's field header at the 64 511-byte bound, the future bound with `received_at` before `now`, the exact verdicts at the time extremes, a `Debug` that prints the body as numbers (U-A1–UA3, U-B E17, E40–E44, P03–P08, P22, P32, P36) | Low | T02, T11, T12, T13, T16, T17 and T18 carry the cases; each of those mutants now fails a test |
| AU2 | A vector could lose its point with every test green: a `mutate_*` byte outside its region, `signed_ciphertext_only` without its counter flip, `key_retired` below the last counter, expiry or future bounds one step off, records that lost the field their name is about (U-B S07–S27) | Low | The dispatch checks each edit against `text_k1`; the script requires each vector's shape; two tautological requires dropped (U-A16) |
| AU3 | Literals that derive from others, the padded-length rule written twice, the `Forged` mapping written twice, an error after the message was consumed, missing doc lines, `PartialEq` on content outside tests (U-A4–UA10) | Low | Derived constants, `record::FIELD_HEADER_LEN` shared, `is_padded_len`, `bad_signature`; `Unreadable` for a failed slice; docs; `cfg_attr(test)` |
| AU4 | T16 in one test of 170 lines; T20 always at the last counter and always with a name; T21 only up to k = 3; T10's out-of-order case tested a missing key instead (U-A13, U-A15, U-C5–UC7) | Low | T16 in four tests; T20 over any counter and an optional name; T21 over every k; T10 as the vector's shape |
| AU5 | The spec's Interface lacked `PayloadHead`, and said `open` calls `decode`; T02 named k = 65 as the first length above the class; T06 and T11 named the wrong proof (U-A D1, U-C2, UC4, UC8) | Low | Interface, T02, T06, T11 |

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AU-Q1 | R12 did not say whether a stale record with no key 0 is `Stale` or `Unreadable`, and no vector fixed it, so two platforms could disagree (U-A D2, U-C1, U-B P30) | `Stale`: the absent key 0 is judged with the `type`, after the stale check, as §4 step 7 lists it | R12, T16, vector `stale_missing_type` |
| AU-Q2 | Audit T left open whether the header keystream is wiped (U-C11) | Not wiped: it opens only what the receiver keeps, as audit H (H55) decided | Security of spec 013 |
| AU-Q3 | AGENTS 22 said "no exceptions", against the tests' `assert_eq!` of the rust skill and the exception for public identifiers decided in audit J (021-R9) and never written in (U-C12) | Rewrite | AGENTS 22 and the `sodium_memcmp` row of `docs/spec.md` §4: production code, keys, signatures and anything secret-dependent always `ct_eq`; tests and public identifiers used as map keys or for ordering exempt |
| AU-Q4 | The three slices are 473, 1 035 and 614 net lines against the 400 of AGENTS 14 (U-A D3, U-C3) | Accept, most of it is tests | History of spec 013; each excess stated in its commit |

Not changed: the mutants that survive are equivalent — `wrapping_mul` in `ttl_ms` (a `u32` times 1 000 fits), step 2 without `min` (the same verdict for either order of the times), `saturating_sub` for the blob length (0 blocks is still `BadLength`), `sent_at` left out of `Debug`, and script mutants that move a byte within its region or change a bad record into another bad record. Test names that reuse a T for a closely related check (`s013_t10_r06_encode_decode_round_trip`, `s013_t20_r16_seal_padded_checks_its_length`) stay, since each covers the requirement it names (U-A12). ADR 0027's wording of the stale point is looser than §4 step 7, which is canonical and refines it (U-C10).

## Audit T

**2026-09-29 — Audit T, code audit of spec 012-message-keys (branch `012-message-keys`), in three independent passes (T-A: structure and simplicity; T-B: the local CI run, 46 mutants of the Rust code and 14 of the reference-script section, probes of the edge cases, the script's XChaCha20 against libsodium; T-C: conformance with spec 012, `docs/spec.md` §4, ADR 0002, 0013, 0018, 0032 and the specs that consume it).** CI green; no defect in the code; the values of every vector are unchanged. No question needed the human reviewer. Findings (numbered AT) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AT1 | Three vectors could lose their meaning with every test green: `message_key_other_sender` with the first sender, `message_key_max` below 2^64 − 1, a `header_sealed` counter whose bytes repeat (T-B S09, S10, S12) | Low | Guards in the script section; its helpers `header_bytes`, `header_keystream` and `xor`, which spec 013's section will reuse (T-C8) |
| AT2 | Nothing held R6's single error mapping: a local `map_err` to another variant passed, since libsodium does not fail in a test (T-B K18, K19, H23) | Low | T08 asserts that `keys.rs` and `header.rs` contain no `map_err` |
| AT3 | T07 claimed every byte of the keystream differs and asserted one; T05 mostly tested XOR and omitted two cases the spec names; T02 checked its own helper and repeated T04 (T-A2, T-A3, T-A5, T-C3, T-C4) | Low | T05 and T07 assert what they say; T04 keeps the negatives; the spec's test cases amended |
| AT4 | As in audit S, the tests named vectors that only the dispatch loads (T-C2) | Low | Interface sentence; T01, T02, T05, T10 |
| AT5 | The Interface did not state the traits `ChannelKeys` and `Header` implement, nor why `Header` is not `Copy`; R5 named only one failure (T-C5, T-C6) | Low | Interface; R5 |
| AT6 | The Context said three platforms check these vectors, which spec 040 says the bindings do not reach; the `header_sealed` row listed fewer fields than it carries (T-C7, C2) | Low | Context; Vectors |
| AT7 | Duplicated zip loops and a bare `40` in `message_key`, hand-written XOR loops, three copies of the key derivation in the checkers, a weaker T09 than 011's, uneven docs and `# Errors` wording, a stale `proto.rs` module doc (T-A1, T-A4, T-A6–T-A11, T-A13) | Low | `concat` in `message_key`; one `xor` and one `keys(k_ch)` per test module; T09 checks the formula lines of §4; docs |

Not changed: the slice is 460 net lines against the 400 of AGENTS 14, since the audit's trims were offset by the script's guards and the rest is tests; it ships as one slice, stated in the spec's History, rather than the two the spec allows (T-A12, T-C1). The mutants that survive are equivalent: a `swap_bytes().to_le_bytes()` counter, and a hand-written `Debug` that prints the same text. `header_keystream` returns a plain array that is not wiped; it is not a key, and whether it should be is left to spec 013, where it is used (T-C12). AGENTS 22 says "no exceptions" while the rust skill lets tests use `assert_eq!` on byte arrays; the tests of every spec already follow the skill, and the wording is left for the human reviewer (T-C, C1).

## Audit S

**2026-09-29 — Audit S, code audit of spec 011-config-format (branch `011-config-format`, slices (a)–(e)), in three independent passes (S-A: structure and simplicity; S-B: the local CI run per commit, 131 mutants of the Rust code, probes of the edge cases; S-C: conformance with spec 011, `docs/spec.md` §4, §5, §9, the ADRs it cites and the specs that consume it).** CI green at every commit; no correctness defect in the code; the bytes of every record, QR text and file are unchanged. The human reviewer decided four questions (numbered AS, so that they do not read as requirements):

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| AS-Q1 | The hand-written base64url decoder took a time that depended on each character of a text that carries `K_ch`; libsodium ships the same codec, strict and in constant time (S-A20, S-C21) | libsodium | Spec 010 R19, `crypto::base64url_encode` and `base64url_decode` over `sodium_bin2base64` and `sodium_base642bin`, `CryptoError::BadEncoding`; `proto/base64url.rs` deleted; specs 011 and 014 amended |
| AS-Q2 | Only `config_reference` carried a QR text, though specs 040 R13 and 054 T16 import the record vectors by QR (S-C4, C3) | Every record vector | R22, Vectors: each vector with a `record` carries `qr`, checked through `parse_qr` |
| AS-Q3 | Rejections the platforms reach had no negative vector, against `specs/vectors/README.md` (S-C, C4) | Add them | 14 negatives: `record_repeated_key`, `record_missing_key`, `record_missing_key_1`, `record_non_utf8`, `qr_plus`, `qr_slash`, `qr_684_bytes`, `file_4_bytes`, `file_1084_bytes`, `file_1086_bytes`, `password_empty`, `password_not_utf8`, `password_canonical_257`, `password_not_whitespace`; `password_too_long` now over the typed bound only (S-B9) |
| AS-Q4 | Which characters count as whitespace in R15 differs between Rust, Java and Swift (S-B12) | A vector | `password_canonical`; the script writes Unicode `White_Space` out; R15 names U+001C..=U+001F and U+FEFF as kept |

Findings and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AS1 | The index derivation of the drawn password was untested: a mask of 10 bits or one byte read twice (56 bits) passed (S-B) | Medium | `password_of`, pure, with a known answer per index bit (T16) |
| AS2 | Nothing checked that `export_encrypted` draws a fresh salt and nonce (S-B) | Medium | T16 compares both regions of two exports |
| AS3 | The check orders R3 and R13 fix were not all pinned: expiry before ranges, the version read before key 1, the length before the version byte, and `>=` against the QR bound all passed (S-B, S-C10, S-C11) | Low | Cases in T03, T04, T11, T13 (`bad_headers`) |
| AS4 | The largest valid config was never exported, so a writer of 400 bytes passed (S-B, S-C8) | Low | `s011_t24_r24_round_trips_the_largest_config`; the T24 strategies reach hosts of 244 bytes, names of 64 bytes and ports of 65 535, and assert the grammar rather than discard what it rejects |
| AS5 | Grammar and range gaps: `8` and capitals in an onion host, `_` in a host, a grammar too strict on `-`, the ends U+001F, U+007F, U+009F of Cc (S-B) | Low | `good_urls`, `bad_urls`, `out_of_range` |
| AS6 | The drawn password's buffer could grow, and T15 and T19 checked the canonical capacity on three inputs (S-B, S-C9) | Low | T19 asserts 62; the T15 proptest asserts the capacity over UTF-8, long ASCII and arbitrary bytes |
| AS7 | The `config_reference` checker derived the QR expiry from the vector itself, so a script that wrote the wrong expiry passed (found re-running the script mutants) | Low | The checker exports at `created_at` |
| AS8 | R12 and T12 said the codec rejects the 684-byte text; tests named vectors that only the dispatch may load; the Vectors table said `chatcfg_reference` seals `config_reference`; the Interface missed `error/tests.rs` and said every `proto` function returns `core::Error`; R19 promised no copy on a move; `seal_file`'s canonical input was unstated (S-A4, S-A19, S-C1, S-C2, S-C5, S-C6, S-C13–S-C15) | Low | Spec 011 amended, no requirement renumbered; spec 014's `verify_qr` returns a `Result` |
| AS9 | `export_encrypted(u64::MAX)` ran Argon2id before failing (S-C17); `== [VERSION]` on an array against AGENTS 22 (S-C3) | Low | Expiry checked first; the version byte compared as a `u8` |
| AS10 | Structure: three near-identical negative checkers, `url::Parts::port` never read, missing `# Errors` on the `pub(crate)` seams, a three-step header split, a double binding, `step_by` pairs, a public `MAX_RECORD`, names shared by a free function and a method, the doc of `Internal`, tests out of T order and without a module doc, a script section that built its vector dicts five ways and a first-run branch that could no longer run (S-A1–S-A3, S-A6–S-A9, S-A11–S-A18) | Low | One `check_negative` over every form a vector carries; `url::parse` returns the host; docs; `as_chunks`; `derive_channel_id`, `derive_channel_keypair`, `from_checked`; `raw_011`, `encode_value` shared with 017, guards on `record_513_bytes`, `qr_length_mod_4`, `qr_684_bytes` and `password_not_utf8` |
| AS11 | Commit ccaacd4 edited the accepted spec without a History line (S-C19) | Low | History line |

Not changed: slices (b) and (e) are 737 and 629 net lines against the 400 of AGENTS 14; S-A found about 50 lines of trim, applied here, and splitting further would separate tests from the code they test, so the excess stays stated in the commits for the human reviewer (S-A21, S-C18). The mutants that survive are equivalent: the `MAX_QR` comparison beyond 684 (R7 rejects any longer text), the second `parse_file_header` in `open_file_with_key`, the capacity of the file buffer and of `padded_record` (no observable copy), a wider `reader.text` bound (`check_ranges` applies the same), `rsplit_once` for the port. `docs/spec.md` §9 lists fewer `Error` variants than spec 027 R18 (C5): 027 updates §9 when it lands, and 011 R20 names §9 as it stands. The URL grammar stays private to `config` until specs 020, 027 and 031 need the scheme or the port (S-C20).

## Audit R

**2026-09-28 — Audit R, code audit of slices (a) and (b) of spec 017-record-encoding (branch `017-record-encoding`), in three independent passes (R-A: structure and simplicity; R-B: the local CI run, 63 mutants of the codec and the test schema, mutants of the reference-script section, edge-case probes; R-C: conformance with spec 017, `docs/spec.md` §4 and the specs that consume the codec).** CI green; no correctness defect in the codec; no wire, key or format decision changes. Findings (numbered AR, so that they do not read as requirements) and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| AR1 | `end()` walking a single field survived every test: no test or vector had a skipped field followed by trailing bytes (R-B) | Medium | T05 case and vector `unknown_key_then_extra_byte` |
| AR2 | The vectors did not pin the integer byte order: every integer vector was a palindrome in bytes, so a little-endian reader in another language would pass (R-B) | Medium | Vector `all_fields`, with integers whose bytes all differ; it is also the six-field seed spec 016 T03 asks for (R-C) |
| AR3 | The limits 512 and 64 were tested only against the constants under test; `MAX_RECORD = 511`, `MAX_TEXT = 63` and a writer capacity of 150 in `encode` survived (R-B) | Medium | Literals pinned in T08; vector `record_at_limit`; `all_fields` carries `bytes` and `text` at 64 bytes and re-encodes 203 bytes |
| AR4 | A getter asked for a key below the last one returned a silent `None`, so a schema decoder with its keys out of order would read a present key as absent (R-B) | Medium | `KeyOrder` from the getter; Interface; T02 |
| AR5 | T07 checked only the error, never the value read after a skipped key (R-B) | Low | T07 reads key 5 after a skipped key 3 |
| AR6 | R4 did not fix which error a `text` both too long and not UTF-8 returns (R-B, R-C) | Low | Length first, in R4; T04 |
| AR7 | When the reader decides an absent key was not stated, though specs 011 R3 and 013 R12 depend on it (R-C) | Low | Interface sentence |
| AR8 | T01 contradicted the Interface and spec 015 R3 on who loads `017.json`; the code took the Interface's reading (R-C) | Low | T01 reworded |
| AR9 | The vector fields other than `schema` and `policy` were not named, though spec 016 R8 and the other platforms read them (R-C) | Low | Vectors paragraph |
| AR10 | T03 did not re-encode the maxima; R11's value above 2^32 − 1 had no test (R-A, R-B, R-C) | Low | T03 round trip; T11 on 64-bit targets, where zeroed pages are mapped lazily |
| AR11 | Missing `# Errors` docs, a module doc calling the envelope a record, `skip_unknown` that skips nothing, a `fixed` helper, table and policy idioms unlike the surrounding code, the Python `expected` that encoded and discarded, bare `5` and `65`, origins that named no document (R-A, R-C) | Low | Docs; `unknown_key`; `fixed` removed; `Fields` alias; `schema_value`, `FIELD_HEADER_LEN`, origins prefixed with "spec 017 test schema" |

Not changed: slice (a) is 463 net lines against the 400 of AGENTS 14 (R-A, R-C); R-A found about 15 lines of trim that keep every case the spec names, so the excess is stated in the commit and left to the human reviewer. A failing proptest writes `proptest-regressions/`, which `.gitignore` does not list (R-B); a green run writes nothing, and whether to commit such files is left open.

## Audit Q

**2026-09-28 — Audit Q, first code audit: slices (a) and (b) of spec 015-test-vectors (branch `015-loader`), in three independent passes (Q-A: structure and simplicity; Q-B: the local CI run per commit, loader edge cases and mutants of the loader and the reference script; Q-C: conformance with spec 015 and AGENTS).** CI green at both commits; no wire, key or format decision changes. Findings and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| Q1 | The escape and control-character rules of the loader had no test that failed without them (Q-B) | Medium | Two edits without a quote in `s015_t01_r01_rejects_every_broken_rule` |
| Q2 | The self-check never called the script's `blake2b_256`; `digest_size` or a dropped `key` survived (Q-B) | Medium | Checked against both BLAKE2b vectors of `010.json`; R4, T04 |
| Q3 | The import check walked `globals()` and missed an import inside a function (Q-A, Q-C) | Medium | Parses its own source with `ast`; R4 |
| Q4 | T02 called `load` outside `crypto/tests.rs`, against the Interface (Q-C) | Medium | Loop removed |
| Q5 | T05 promised every written file loads under R1, but a section could hand `render` raw dicts (Q-C) | Medium | Every value goes through `vector`; R5, T05 |
| Q6 | `Vector.source` and `origin` stored and never read, hidden by the module's `dead_code` allow (Q-A) | Low | Fields removed; still checked on load |
| Q7 | Every field looked up twice, with an unreachable error (Q-A) | Low | `exact` returns the values; `field` removed |
| Q8 | The 010 vectors retyped in the script with nothing checking the copy (Q-C) | Low | The script reads `010.json` for its self-tests; R4 |
| Q9 | Unicode whitespace accepted between tokens (Q-B) | Low | JSON whitespace only; R1 |
| Q10 | R1, T01 and the Limits table said less than the loader enforces, and T01 put the 64-bit check in the loader (Q-C) | Low | R1, T01, Limits, `specs/vectors/README.md` |
| Q11 | R5 required five files the format specs have not written yet (Q-C) | Low | R5 writes the file of every section present; phase 1 exit criterion (§10) requires all five |
| Q12 | Minor: `check_all` checked its three rules three ways, `FILES` had a fixed size, a KDF `subkey_id` that is always 0, the word-list check skipped silently, a stale comment, `Clone` unused (Q-A, Q-B) | Low | Simplified |

## Audit P

**2026-09-28 — Audit P, coverage review of the whole plan once every spec of §10 existed, in three independent passes (P-A: every obligation of `docs/spec.md` §1–§12 and `docs/threat-model.md` mapped to the spec that owns it; P-B: every deferral between specs checked against its target; P-C: what a v1 shipped to the stores needs that no spec covers).** No wire, key or format decision changes. The human reviewer decided two questions:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P-Q1 | No spec ran the project's own server at `DEFAULT_SERVER_URL`, yet the beta needs it, the privacy policy makes promises about it and `SECURITY.md` promises redeploys (P-A7, P-B1, P-C2) | A spec of its own | Spec 066-public-server; §10, §11 |
| P-Q2 | Nothing covered the time after the public release: security patch releases, telling direct and APK users a fix exists, store and toolchain deadlines, dependency upkeep beyond Actions (P-C1, P-C8) | A spec of its own, not folded into 060 or 064 | Spec 065-release-maintenance; §10, §11 |

Drafting choices, recorded for the review:

| # | Choice | Where |
| --- | --- | --- |
| P-D1 | `Unreadable` shows the text of §4, "unsupported or corrupt message", next to the sender | Spec 056 R8 |
| P-D2 | No image registry in v1: the server image's digest is its `SHA256SUMS` line and self-hosters build it from the tag | Specs 001, 062 R1, 064 R2, 066 R2 |
| P-D3 | `docs/residuals.md` keeps collecting only the exact phrase "documented residual"; the specs that said it in other words were reworded | Specs 032, 041, 061 R2, 062 |
| P-D4 | WebView2 with `webviewInstallMode: skip` on Windows 11 only: no download from Microsoft at install time and no 127 MB vendored installer | Spec 050 R13 |
| P-D5 | Accessibility services are not detected on Android: a warning would fire for every screen-reader user; a documented residual | Spec 053 |
| P-D6 | Phase 1 closes only with a "Phase 1 review" row naming the second reviewer of `proto` and the commit read | Spec 016 acceptance |
| P-D7 | The public release gates on every spec of the index but 064 being `implemented` (065 and 066 included), the export-compliance record, the EU-rules question of 066 closed and spec 066's server running the release image; phase 6 closes with 064 (round 2) | Spec 064 R1 |
| P-D8 | A list of community servers, if ever kept, lives on the landing's "Run your own server" page only | §12; spec 062 R1 |
| P-D9 | Store screenshots in the five languages come from the UI and screenshot tests over invented content | Specs 051 R10, 052 R10 |
| P-D10 | One export-compliance checklist (EAR, France, the App Store key) in `docs/release-legal.md`, reused by every store; open question 052-R10 for the owner | Specs 051 R10, 052 R10, 064 R1 |
| P-D11 | A screen reader announces "New message" alone, at most once every 2 000 ms, when the focus is off the open channel's list, never for a muted peer | Specs 050 R14, 056 R7 |
| P-D12 | A build older than its tag plus 180 days shows a line that blocks nothing and fetches nothing; moved to spec 056 in round 2 so that v1.0.0 carries it, with a release due before the newest tag is 180 days old | Specs 056 R22, 065 R4 |
| P-D13 | Unlock measured before the beta on an API 30 phone with 16 channels near the log cap; the beta ends only at 10 000 ms or less | Spec 063 R6, R8 |

Findings and changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| P1 | The project's public server had no owner (P-A7, P-B1, P-C2) | High | P-Q1 |
| P2 | No maintenance after the release; Dependabot covered three of the lock files and no scheduled advisory check ran (P-C1, P-C8, P-A3) | High | P-Q2 |
| P3 | iOS had no privacy manifest, which App Store Connect requires (P-C4) | High | Spec 052 R11 |
| P4 | Export compliance only for iOS; nothing for Play, F-Droid or the downloads (P-C3) | Medium | P-D10 |
| P5 | Store review: no reviewer notes, no answer on user content or age rating, no IPv6-only check; screenshots excluded everywhere (P-C5, P-B3) | Medium | Specs 051 R10, R11, 052 R10, R12; P-D9 |
| P6 | Third-party licence notices were not shipped (P-C6) | Medium | Spec 060 R12; Help "Licences" (056 R18) |
| P7 | No desktop platform floors; the default WebView2 bootstrapper downloads from Microsoft at install (P-C7) | Medium | Spec 050 R13; P-D4 |
| P8 | Security warnings and store listings were translated with no reviewer (P-A10, P-C17) | Medium | Spec 062 R7; 055 R3 and 056 R3 mark their security texts |
| P9 | Tor on iOS unverified; `.onion` channels may be unreachable on iPhone (P-C12) | Medium | Spec 052 R13, open question 052-R13; Help (056 R18) |
| P10 | `CounterExhausted` showed a text but did not force regeneration (P-A9) | Medium | Spec 056 R12 |
| P11 | Several §8 and §2 "documented" promises would never reach `docs/residuals.md` (P-A11, P-A13–P-A15, P-C13, P-C14) | Medium | P-D3; residuals in 023, 032, 041, 053, 062 |
| P12 | No rule that a later app reads every earlier local file version, and no golden files (P-C9); server schema upgrade unstated (P-C10) | Low | Spec 020 R31; spec 032 R3 |
| P13 | Desktop keyboard and screen-reader use, announcements, the QR's 60 s under timing rules (P-C11) | Low | Specs 050 R14, 054 R6, 056 R7; P-D11 |
| P14 | The landing as a site had no owner; the privacy policy omitted its host's logs (P-A4, P-C16) | Low | Spec 062 R1, R2, R8 |
| P15 | Phase exits "internal review of `proto`" and "no spec left in draft" had no check (P-A1, P-A6) | Low | P-D6, P-D7 |
| P16 | Unlock time with many channels never measured (P-C15) | Low | P-D13 |
| P17 | Uninstall leaves data and key; device PIN over biometrics only in Help (P-C14, P-A17) | Low | Spec 053 residual and R5/R19 text; Help (056 R18) |
| P18 | Building libsodium from source on Windows bounced between 042 and 060 (P-B5) | Low | A v1 documented residual in both |
| P19 | Local CI equivalents of the client and Docker jobs not required in `CONTRIBUTING.md` (P-A16) | Low | Specs 034 R8, 053 R16, R22 |
| P20 | About fifteen stale pointers to 050–052 where 042, 053, 055 or 056 own the thing; 012 named functions 021 does not have; 035's History named a missing 041 R18 (P-B7–P-B16) | Low | Wording in 011, 012, 021–026, 028, 034, 035, 055 |
| P21 | Open questions left unticked in the implemented specs 000–003 (P-B17) | Low | Closed with their proposals; 002-R4 closed as no script |

Round 2 (two passes over the round 1 diff: coherence, and adversarial security with technical viability; about 50 findings, consolidated):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| P22 | The public server's image check took its key from the repository, so whoever held GitHub chose what the server ran; the server rebuilt on a machine sized for connections; "any member can compare" overstated it | High | The image is built off the host and loaded; the signature is checked against fingerprints written on the host out of band; which code runs is a documented residual (spec 066 R1, R2) |
| P23 | The age notice and the feed would ship only after v1.0.0, missing the users they exist for | High | The notice is spec 056 R22; 064 gates on 065 and 066 being `implemented`; phase 6 closes with 064 |
| P24 | Every patch tag broke 061 R3's rule for the release tag; nobody owned re-reviews after the release | High | 061 R3 binds the first public tag only; 065 R1 asks for a new review for a change to 011–017 or the crypto and proto paths, and lists every other change `unreviewed` |
| P25 | Licence notices would fail every Android build, since many packages ship no licence file | High | Reviewed `licenses/overrides/` (spec 060 R12) |
| P26 | Desktop floors named unsupported systems and arm64 Linux that no build produces; the WebView2 text sent users to Windows Update | Medium | macOS 15, Windows 11, Linux x86-64, dated; WebView2 check its own R (spec 050 R13, R15) |
| P27 | IPv4 literals are synthesised on Apple's NAT64 only through `getaddrinfo` | Medium | The host resolves every name through it on Apple targets; open question 042-R9 on the dependency (spec 042 R9; 052 R12) |
| P28 | Leaving France out of the stores does not keep direct downloads and F-Droid out of France | Medium | The ANSSI declaration is mandatory (spec 052 R10) |
| P29 | Certificate threshold fixed at 14 days against 45-day certificates; scheduled workflows stop after 60 idle days; memory sized with no headroom; untested port claim | Medium | 7 days, a documented residual and a 065 R4 row, 70 % of measured memory, an owner's `nmap` record (spec 066) |
| P30 | Disclosure before the stores carried the fix; Dependabot cannot update Gradle's verification metadata; scheduled jobs only see the default branch | Medium | Advisory after the stores or at 7 days; owner's metadata commit; a two-branch matrix (spec 065 R2, R5, R6) |
| P31 | The landing's attribute scan missed preconnects, forms and SVG links; the legal route and the feed were not among its pages | Medium | A CSP meta on every page and a headless-browser check; seven routes (spec 062 R1, R8) |
| P32 | Security texts of 053 and 054 not marked for the reviewer rule; 055 and 056 cited the wrong 062 requirement; the client log lint matched `fingerprint(` | Medium | Marked; 062 R7; word-bounded patterns (specs 053 R19, R22, 054 R4, 055 R3, 056 R3) |
| P33 | Wrong or missing cross-references, asymmetric Depends and Blocks, a rewritten History line, two statements of the announcement rule, Tor Help text in two places | Low | Corrected; the rule in 056 R7 alone, the Tor text in 056 R18 alone, the measurement in 052 |


## Audit O

**2026-09-27 — Audit O, review of the phase 6 draft specs 060, 061, 062 and 063 before human review, in four independent passes (O-A: coherence and SDD conformance; O-B: adversarial security and supply chain; O-C: technical viability, measured with rustc 1.98.1, Docker 29.8 and buildkit, apksigner from build-tools 36 on JDK 22, OpenSSH 10.3 and git 2.54, and read from tauri-bundler 2.9.4; O-D: end-to-end scenarios).** The human reviewer decided six questions with the recommended option (O-Q5 and O-Q6 in round 2):

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| O-Q1 | Google Play requires an app bundle for a new app and signs what users install with Google's key, so Play testers would run neither the owner-signed nor the reproducible build (O-B3, O-C1, O-D6, O-A5) | In the closed beta, Android is distributed like the desktop: the owner-signed reproducible APK by private link. Google Play is decided for the public release, with Play's signing a documented residual like iOS and Android code transparency signed with the owner's token | Specs 060, 063; spec 064 |
| O-Q2 | A critical or high review finding the project believes wrong had no way to close, so the beta could never start (O-D20) | It closes only when the reviewers withdraw or downgrade it in writing after reading the project's response, which the published report carries | Spec 061 R6, R7 |
| O-Q3 | A public page or the beta letter with no reviewer in one of the five languages would block the beta (O-D24) | That language shows the English text until a translation is reviewed; the beta does not wait, and no unreviewed translation is ever shown | Specs 062, 063 |
| O-Q4 | No spec covered the public release after the beta: the Beta label, the production stores, F-Droid, public download links, the "experimental" line (O-D28) | A short spec 064-public-release in phase 6 | Spec 064; §10 |
| O-Q5 | Nobody outside GitHub rebuilt the Windows artefacts, so a compromised CI could ship a Windows installer the owner would sign (round 2, O-B B1) | The owner rebuilds them on a Windows virtual machine of his own before signing; until it exists, releases leave Windows out | Spec 060 R6 |
| O-Q6 | An attacker holding GitHub and the landing host could show one person a forged release (round 2, O-B B4) | The signed manifest of every public release is logged in Sigstore Rekor, and the verify script checks it; beta and rc manifests are not logged | Spec 060 R8; spec 064 |

Round 1 (about 94 findings, 8 of them blockers, consolidated):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| O1 | Both CI builds and the verification ran on the same GitHub account and dependencies, so a compromised workflow, action or dependency could build one backdoor twice and get it signed (O-B1) | Blocker | The owner rebuilds locally, outside GitHub, before signing; actions pinned by commit, read-only permissions, no install scripts; a Security line on malicious locked dependencies (spec 060) |
| O2 | Every trust anchor (the allowed signers, the keys document, the verify script, the verify page) came from the repository an attacker would control (O-B2, O-C8, O-D12, O-A21) | Blocker | Fingerprints published out of band (F-Droid's metadata, the review report, the app's Help, the beta letter); the verify script takes or pins the fingerprint; the tag check reads the previous release's signers (specs 060, 056 R18, 063) |
| O3 | The CI verification needed the signature that only exists after the owner signs (O-D1, O-A1) | Blocker | A build job writing the unsigned hashes, and a verify job on the published release (spec 060) |
| O4 | The acceptance tag did not fit the tag grammar, and nothing told a beta build from a release one (O-D2, O-D10, O-A2, O-A10, O-C17, O-C21) | Blocker | `-rc.N` and `-beta.N` suffixes; the beta flag compiled from the tag (specs 060, 063) |
| O5 | The F-Droid check could never pass before the beta, which the beta's gate needed (O-D7, O-A3) | Blocker | An automated `apksigcopier` check in 060; F-Droid in 064 (specs 060, 064, 051 R10) |
| O6 | Google Play signs its own build (O-B3, O-C1, O-D6, O-A5) | Blocker | O-Q1 |
| O7 | The delta after the frozen commit covered a fraction of the reviewed paths, and the beta build was not tied to what was reviewed (O-B9, O-D17, O-D18, O-A18) | High | Every reviewed path, the lock files, `vendor/` and the toolchain; the reviewers confirm the delta; the beta tag is the review tag plus acknowledged rows (spec 061 R3) |
| O8 | The privacy policy and the beta letter understated what is kept: blob metadata to the TTL, addresses 60 s after a connection, hosting logs, store and platform data, crash logs and TestFlight feedback (O-B11, O-B13, O-C22, O-D23, O-A20) | High | Each corrected, retention sentences taken from specs 032 and 033, the controller named (specs 062, 063) |
| O9 | A lost token had no safe way out, and one token per key made the owner a single point (O-B5, O-B6, O-D11) | High | A backup token per key, APK v3 rotation, rotation signed by a valid key, a touch for every signature (spec 060) |
| O10 | The public GitHub release contradicted a closed beta (O-D9, O-A6, O-C12, O-B16) | High | Draft releases for `-beta` tags; artefacts by private link (specs 060, 063) |
| O11 | One script on one machine could not sign for macOS and Windows, made network requests it denied, and had no iOS step (O-D5, O-A7, O-C10, O-C11, O-C13) | High | A host per step, `osslsigncode` for Authenticode, the allowed endpoints, the iOS signing and upload (spec 060) |
| O12 | Signed installers and the macOS zip are not "unsigned plus a signature"; a removed Mach-O signature does not restore the file (measured) (O-C2, O-C3, O-B4, O-D29) | High | Installers rebuilt from the signed binaries; comparison after stripping both; an "unchecked" state; the residual stated (spec 060) |
| O13 | Tauri's `.deb` and AppImage are not deterministic and fetch tools at bundle time (O-C4, O-C5, O-B7, O-D30) | High | A deterministic repack; the tool cache pre-seeded with pinned copies (spec 060) |
| O14 | Two runners with different images contradict determinism; paths of dependencies and of crates outside the workspace leak into binaries (measured) (O-C6, O-C7) | High | One pinned toolchain, different hosts and paths; the repository root and `CARGO_HOME` remapped by a wrapper (spec 060) |
| O15 | The apksigner PKCS#11 form fails on JDK 22 (measured) (O-C9) | Medium | The provider configured through `java.security.properties` (spec 060 R5) |
| O16 | A disputed high finding had no exit; an ADR closed a high finding with no reviewer sign-off (O-D20, O-B10) | High | O-Q2 (spec 061) |
| O17 | Security fixes during the beta, the re-review rule and the testers' updates were undefined (O-D14–O-D16) | High | Release branches from the reviewed tag; the fix ships and is a delta row; the beta pauses on an open critical or high; updates announced by mail (specs 060, 061, 063) |
| O18 | No spec covered the public release (O-D28) | High | O-Q4 (spec 064) |
| O19 | The beta gate was checked only when the beta ended (O-D26) | High | A start row checked by the lint (spec 063) |
| O20 | The residual lists were tangled across 061 and 062, missed residuals worded otherwise, and could not take review acceptances (O-A16, O-A17, O-D21, O-D22) | Medium | 061 owns `docs/residuals.md`; 032 and 033 reworded; acceptances also written into the spec (specs 061, 062, 032, 033) |
| O21 | The public pages' checks had nothing to compare (the landing builds from `docs/`), JSON has no comments, one-language forbidden words, and no translation sync (O-A13, O-A14, O-B12, O-D24) | Medium | Pages built from `docs/`, a `source` field per entry, per-language word lists, the English hash in each translation, O-Q3 (spec 062) |
| O22 | The beta log and the server's view could re-identify a small known group (O-B14, O-B15) | Medium | Week and platform family only, private until the end; the letter names the server's view and recommends Tor (spec 063) |
| O23 | Scenario counts could never be met; Help's order conflicted with a beta notice; translations under `docs/` break AGENTS 11 (O-A11, O-A12, O-D27) | Medium | Platforms per scenario; 056 R18 amended; the letter's translations under `landing/` (specs 063, 056) |
| O24 | Build knobs: `SOURCE_DATE_EPOCH` is not read by rustc or cargo; buildkit needs it with `rewrite-timestamp`, no provenance; the zip recipe; libsodium's `optimized` feature is `-march=native`; ssh signing details; Homebrew OpenSSH on macOS; F-Droid metadata fields; Windows code-signing certificate rules (measured or read) (O-C14–O-C16, O-C18–O-C20, O-C23, O-C24) | Medium | Stated (specs 060, 064) |
| O25 | Wording and references: the four skills' real sentences, the server binary is not static, five keys not four, AGENTS 17, MUST NOT, a job trigger that `review-N` tags would hit, "Accepted limits" against "Accepted limitations", the §11 tree, the landing plan, the review question's ADRs, unnamed tests (O-A4, O-A8, O-A9, O-A15, O-A19, O-A21, O-A22, O-C25, O-C26, O-D3, O-D4, O-D13, O-D19, O-D25, O-B8) | Low | Aligned (specs 060–064, 051, 056; `docs/spec.md` §10, §11) |

Round 2 (three passes, O-A, O-B and O-D, about 60 findings, no blocker; O-Q5 and O-Q6 decided):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| O26 | Windows was rebuilt only on GitHub (O-B B1) | High | O-Q5 (spec 060 R6) |
| O27 | A third party ran the verify script from the attacker's clone; a first-time user had no anchor the attacker could not change; the report in the repository and the app's own Help are not independent (O-B B2, B4, O-D D13, D23) | High | A plain `ssh-keygen` check first, against a fingerprint printed in the letter and in the report on the reviewers' own site; the clone's commit checked against the manifest; several fingerprints; Rekor for public releases (O-Q6); Help only for later downloads (specs 060, 061, 056 R18, 064) |
| O28 | The owner ran the tag's own scripts before verifying the tag; tags are mutable; "the previous tag" and a first-key bootstrap were undefined (O-B B3, O-D D2) | High | The tag verified against the owner's own signers file first; protection rulesets; the previous tag defined; the first tag a residual; a new key added by a release the old key signed (spec 060 R1, R6) |
| O29 | `sign_release.sh` published at once; the verify job cannot run on a draft; drafts are unreadable by testers and second verifiers; the private-link host was unnamed (O-A 2, 3, O-D D6, D7, D18, O-B B9) | High | Always a draft; verify by manual dispatch; a local-folder mode; the file host named, in the letter and the endpoints (specs 060, 063, 064) |
| O30 | Hotfixes during the beta failed the review-delta rule; a closed delta kept taking rows; tester reports could not pause or close; the pause rows were missing (O-A 4, 8, 9, 10, O-D D10–D12, O-B B10, B11) | High | The delta open until the end, fix rows shipped while paused and confirmed before resuming; every security report a row counted high until downgraded; "Paused" and "Resumed" rows; pauses outside the 28 days (specs 061 R3, R6, R7; 063 R7) |
| O31 | The Play bundle and its keys did not fit 060; Play's "existing key" option, code transparency's reach and a test that checked nothing (O-A 5, O-D D19, O-B B7) | High | The bundle in 060; the Play keys listed, a Google-generated signing key required, a separate transparency key, the uncovered parts stated, the test on a Play-installed APK (specs 060, 064) |
| O32 | Versions were never derived from the tag, so testers could not update in place (O-D D4, O-A 6) | High | A version scheme from the tag (spec 060 R2; spec 051 R7) |
| O33 | The iOS production build and the Play closed test had no place in the sequence (O-D D8, D9) | High | The release build submitted to App Review; the Play test after the beta's end with a letter variant (spec 064) |
| O34 | A stale translation failed the lint instead of falling back to English; the hash's scope was undefined (O-D D16, D17) | High | English with a reviewed "not translated yet" line; per-page source sections hashed (spec 062) |
| O35 | Backup tokens without PIN, Android key material left behind, no compromise procedure, v3 rotation missing Android 11–12, certificates cannot have backup tokens (O-B B5, O-D D3, D21, D22) | Medium | Resident keys with verification, PIN always, a live-boot generation recorded as destroyed, a sealed named place, a compromise procedure, rotation from API 28, second certificates, retired keys shown (specs 060, 056 R18) |
| O36 | `-rc` builds looked like releases and carried production signatures (O-B B8, O-D D5) | Medium | An "RC" flag, its own namespace, no production platform key, no store upload (spec 060) |
| O37 | The delta and the scope missed lock files, release infrastructure and specs 040 and 041 (O-B B6) | Medium | Added (spec 061 R3, R4) |
| O38 | The release keys might not exist at the review freeze; the package cannot name a commit it is part of (O-D D1, D15) | Medium | The keys slice before `review-1`; the package committed after the tag (spec 061) |
| O39 | Accounts left out of the hardening rule; where the letter's fingerprint comes from (O-B B12, B13) | Medium | The full list; derived from the token, on paper, never beside a link (spec 063) |
| O40 | The privacy policy's server choice, DNS, purge delay, snapshots and live view (O-B B14) | Medium | Corrected (spec 062 R2) |
| O41 | Old signed betas stay genuine forever (O-B B15) | Medium | A compiled expiry and a channel warning (specs 060, 063) |
| O42 | Residual sentences grouped or capitalised were not counted; Play's residuals were only in Requirements (O-A 13, 14) | Medium | One sentence per residual, a case-insensitive check, 064 Security (specs 060, 061, 064) |
| O43 | SECURITY.md wording owned twice; the public release's claim after later changes (O-A 11, O-D D14, O-B B18) | Medium | 061 keeps "experimental until the public release", 064 removes it and names the reviewed commit with the delta (specs 061, 064) |
| O44 | F-Droid's order, tag pattern and fingerprint field (O-A 7, O-D D20) | Medium | Merge, publish, build; a tag regex; the SSH fingerprint in the description (spec 064) |
| O45 | Linux beta bytes downloadable from CI run artefacts; the owner's screen shows what malware would swap (O-B B16, B17) | Low | Only the hash list uploaded, one day; the touch count announced and signatures checked on a second machine (spec 060) |
| O46 | References: Q15–Q18 cited under the wrong section, the residuals owner in §11, 053's store pointer, 063's citations of 056 and 060, 064's of 060, 062's residual citations, the beta letter's content collection (O-A 1, 12, 15–18, O-D D24) | Low | Aligned |

Round 3, two passes (O-A, O-D), final (about 28 findings, 1 blocker):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| O47 | Rekor's entry was needed before the verify run and the release row, but logged only after the row (O-A 1, O-D 1) | Blocker | `sign_release.sh` logs a public manifest right after signing; the row records the entry; open question 060-R8 on Rekor's SSH namespace (specs 060 R6, R8; 064 R1, R2) |
| O48 | A manual dispatch cannot receive files, and the job cannot read drafts (O-D 2) | High | A download URL as the input, checked against the signed manifest (spec 060 R9; spec 063) |
| O49 | The one-line check needed the full public key and did not check the files' hashes (O-D 3) | High | `ssh-keygen -Y check-novalidate` and a comparison of the printed fingerprint, then an exact hash command; the namespace from the tag (specs 060 R8, 062, 063) |
| O50 | A four-part iOS build number is rejected by Apple (O-A 6, O-D 4) | High | One integer (spec 060 R2) |
| O51 | Beta tags excluded ordinary changes and the phase 6 app code; the public tag was not tied to the review; human-decided rows were ambiguous; the "experimental" check outlived the public release (O-D 5, 6, O-A 3, 9) | Medium | Unlisted paths allowed; that code implemented before the freeze; the delta open until the public release; the public tag on the last beta or confirmed rows; the rule and the check fixed (specs 061, 064) |
| O52 | No step signed the Play bundle or the Windows installer and uninstaller (O-A 2, O-D 7, 9) | Medium | Stated with their hosts and touches (spec 060 R6) |
| O53 | A dependency cycle 056 → 060 → 050–052 → 056, and missing edges for 061 (O-A 4, 5) | Medium | 056 needs only 060's slice (c); 061 depends on 060, 040 and 041 (headers) |
| O54 | A compromise notice through channels the owner cannot post to; F-Droid merged before its binaries exist and its description in this repository (O-D 11–13) | Low | The owner's channels; publish then merge; the description in fdroiddata (specs 060, 064) |
| O55 | Scenario counts with a platform left out; builds expiring during a long pause or after the end (O-D 14, 16) | Low | Counted per shipped platform family; a rebuild-only beta tag (spec 063) |
| O56 | Citations and tests: 063's of 060 R9 and 061 R3, 062's of 033 R8, Help tests expecting the command, the §11 tree, the rc namespace in the verify script, T08's unchecked list (O-A 7, 8, 10–12, O-D 10, 15) | Low | Aligned |

**Audit O stops here**, by diminishing returns: about 94, 60 and 28 findings over three rounds. Open before implementation: 060-R3 (Android baseline profiles), 060-R8 (Rekor and the SSH namespace), 062-R2 (the data controller named by the owner), 063-R1 (the product name and `DEFAULT_SERVER_URL`), 052-R10 (export compliance).


## Phase 6 drafts

**2026-09-27 — Decisions taken before drafting the phase 6 specs 060–063.** Not an audit: the human reviewer decided Q12–Q14 with the recommended option before the specs were written.

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| Q12 | Who reviews the cryptographic and threat model from outside (§10, phase 6) | A funded review programme for open-source privacy tools (the Open Technology Fund's Red Team Lab or an equivalent), with a package of documents and code the project prepares; the beta waits for its report | Spec 061 |
| Q13 | Who the beta reaches and how | A closed beta by invitation, of 20 to 50 known people, through TestFlight, a closed Google Play track and signed desktop installers sent by private link | Spec 063 |
| Q14 | Who holds the keys that sign published releases | The human owner, on hardware tokens; CI builds the artefacts reproducibly and a local machine signs what CI built, after checking its hashes; no signing key is a CI secret | Spec 060; the kotlin, swift and typescript-svelte skills at acceptance |

## Audit N

**2026-09-27 — Audit N, review of the phase 4 rework (ADR 0041, specs 040, 041 and 042) and the phase 5 platform drafts (specs 050, 051, 052 and 056, with the amendments to 053 and 054) before human review, in four independent passes (N-A: coherence and SDD conformance; N-B: adversarial security and privacy; N-C: technical viability, measured with uniffi 0.32.2 from Swift, tokio, rustls 0.23.45, tokio-tungstenite 0.30, `cargo deny` and the phone targets; N-D: end-to-end scenarios), in rounds.** The human reviewer decided one question with the recommended option:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| N-Q1 | On `*-windows-msvc`, `libsodium-sys-stable` 1.24.0 does not build from its bundled archive: it downloads `libsodium-1.0.22-stable-msvc.zip` over plain HTTP and checks its minisign signature (N-C3) | The signed zip and its signature are committed under `vendor/libsodium/`, pinned by SHA-256, and every Windows build points `SODIUM_DIST_DIR` at them, so nothing is fetched; on Windows a binary built by libsodium's author runs, a documented residual for spec 060 | Spec 042 (a new requirement and its R3 amendments to spec 010 and 041); spec 041 R14 |

Round 1 (about 66 findings, 5 of them blockers, consolidated):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| N1 | The `FfiSink` adapter's hand-off reorders events (measured: about 3 000 inversions in 20 000), so `locked` could precede content and two blocking callbacks could stall the host (N-B1, N-C1, N-D1) | Blocker | One FIFO drained by one dedicated thread, generation-tagged (spec 040 R5, R6, T06; spec 042 R5) |
| N2 | An own message never appeared after Send (N-D2) | Blocker | `SentView.message` inserted by `client_ref` (spec 056 R7, R12) |
| N3 | A proxy confirmed before a lock could not be applied at its generation (N-A1) | Blocker | `Host::set_socks5_proxy_in` (spec 042 R10; spec 041 R9, R11, T10) |
| N4 | `localhost` is a valid proxy for the core, so the expected `BadConfig` never came (N-A2, N-D8) | Blocker | The client refuses `localhost` before any call (spec 056 R16, T16) |
| N5 | The probe outlived the lock and skipped `before_connect` (N-B2) | Medium | The probe under the generation, aborted by the lock (spec 042 R11, R12) |
| N6 | A server could make a `server_id` equal to a pending `client_ref` and crash or spoof a list (N-B3) | Medium | Keys tagged by kind; a repeated key never crashes (spec 056 R7) |
| N7 | Bodies could spoof rows with newlines, reorder marks with bidi controls, or draw over neighbours (N-B4) | Medium | Bidi-isolated, clipped bodies with marks outside (spec 056 R2) |
| N8 | "Continue" on the phones' settings notice dropped the proxy with no confirmation (N-B5, N-D11) | Medium | The no-proxy confirmation first (spec 056 R4) |
| N9 | The desktop notification's mute check and `notify-rust` ran inside the `Sink`, under the device lock (N-B6) | Medium | A coalescing signal and a task off the host (spec 053 R13; spec 041 R7) |
| N10 | A `before_connect` that locks inline deadlocks (N-A7, N-D10) | Medium | It spawns the lock and returns false (specs 041 R7, 042 R9, 053 R8, R20) |
| N11 | The iOS fallback connection could ask the resolver for an onion host (N-A3, N-B8) | Medium | Only channels in a plan, never onion, never with a proxy (spec 052 R4; specs 040 R10, 042 R3) |
| N12 | `copy_message(text)` let a script put any text on the clipboard (N-B7) | Medium | `copy_message(channel, key)` (specs 053 R14, 050 R4) |
| N13 | Pending to Delivered could fall back or outstay its message; re-reads raced events (N-D3) | Medium | The key and times change on `Delivered`; stale re-reads dropped (spec 056 R7, R11) |
| N14 | `channels()` went stale after create, rename, leave, remove and a named send (N-D4) | Medium | Added re-read triggers (spec 056 R11) |
| N15 | Results that return after a lock put content back in view models (N-D5) | Medium | An unlock epoch (spec 056 R21) |
| N16 | Kotlin's `withContext(NonCancellable)` still drops the result of a cancelled caller (N-D6) | Medium | Calls run in `Core`'s own scope (spec 040 R9) |
| N17 | Connection states that arrived before a channel was listed were lost (N-D7) | Medium | An app-level map (spec 056 R21) |
| N18 | The iOS lock could be suspended half-way in the background (N-D9) | Medium | `beginBackgroundTask`; the Android lock in the application scope (spec 053 R8, R9) |
| N19 | The first network callback and the merged effect of `network_changed` cut fresh connections (N-D12, N-C12) | Medium | The first report a baseline; a new monitor per unlock; close only sockets older than the last merged call (spec 042 R10; specs 051 R4, 052 R4) |
| N20 | `ProxyRefused` and a stopped Orbot were hard to recover from (N-D13) | Medium | Cleared at `open`; "Try again"; a proxy-specific text (spec 042 R5, R10; spec 056 R10) |
| N21 | `HistoryTruncated` had no mapping (N-A4) | Medium | A banner at once and a re-read (spec 056 R9, R11) |
| N22 | After the notice, settings from a newer app are kept and nothing said changes were not saved (N-A5) | Medium | A persistent banner with "Replace settings" (spec 056) |
| N23 | Unlock outcomes were unmapped, and a panic at every unlock left no way out (N-A6) | Medium | A Locked-screen requirement with "Erase all data" after a failed unlock (spec 056; spec 050 R6) |
| N24 | The Kotlin and Swift vector tests would connect to the vectors' servers (N-A8) | Medium | A refused loopback proxy first (spec 040 R13) |
| N25 | The Android allowlist could not be satisfied without transitive names (N-A9) | Medium | Transitive dependencies as resolved (spec 051 R7) |
| N26 | `qrcode` without features has no SVG renderer (N-A10) | Medium | `features = ["svg"]` (spec 041 R6) |
| N27 | Several calls had no error mapping (N-A11) | Medium | Rows with a generic fallback (spec 056) |
| N28 | Missing reciprocal `Blocks`; stale references in 027, 041, 042 and 053 (N-A12, N-A13) | Low | Aligned |
| N29 | 042 R3's amendment list missed §2, §6's and §9's introductions (N-A14) | Low | Added (spec 042 R3, T03) |
| N30 | Gaps used `presentSender`, which takes a message (N-A15) | Low | `presentPeer` with the stranger fallback (spec 056 R9) |
| N31 | `BridgeEvent` and the test proxy's arguments were undefined (N-A16) | Low | Named (specs 041 R7, 042 Interface) |
| N32 | The phone `cargo check` steps need the target toolchains (measured) (N-C2) | Medium | iOS on the macOS leg with Xcode, Android through `cargo ndk` (spec 042 R14) |
| N33 | Windows libsodium is a downloaded binary (N-C3) | Medium | N-Q1 |
| N34 | Paused-clock tests cannot use real sockets (measured) (N-C4) | Medium | An in-process transport seam under `test-support` (spec 042) |
| N35 | uniffi details: the `tokio` runtime attribute is unneeded, `catch_unwind` needs `AssertUnwindSafe`, constructors must be fallible, async methods need a helper in `api_surface.rs`, the runtime must be taken out in `Drop`, and `Core` cannot be its own sink (measured) (N-C5–N-C9, N-C14) | Low | Spec 040 R1, R2, R4, R5, R9 |
| N36 | The lifecycle order holds for sequential callers only (measured) (N-C11) | Low | Wording (specs 040 R9, 042 R4) |
| N37 | Tauri's runtime handle is not a tokio handle (N-C13) | Low | `.inner().clone()` (spec 041 R10) |
| N38 | `ClientHello` equality needs a fixed random source; `rcgen` defaults pull `aws-lc-rs`; the `user-agent` name goes out lowercase (N-C15, N-C16) | Low | Spec 042 T09, R9 |
| N39 | Unflushed pongs, unawaited frames, fixed clocks in release, the `Failed` record lost at restart, `ServerFull` always back to `Connected` (N-B9–N-B12, N-D14) | Low | Spec 042 R6, R7, R10; spec 040 R5 |
| N40 | Returns from Settings and from a vanished channel, the lifetime unit, Android before `Core.create`, a custom lock time, `localeConfig` below API 33 (N-D15–N-D19, N-C17) | Low | Specs 056, 051 |


Round 2 (about 66 findings, 2 of them blockers, consolidated; no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| N41 | With `SODIUM_DIST_DIR` set, the build script opens `LATEST.tar.gz` there first on every target, so vendoring the Windows zip alone breaks every build (measured); Cargo reads `[env]` from the working directory, and the build does not rerun when it changes (measured); a pull request could swap the zip, its signature and its hash together (N-B1, N-B2, N-C1, N-C2) | Blocker | Four files with their exact names, `LATEST.tar.gz` byte-identical to the crate's archive, the minisign key and the zip's hash written in the spec and checked independently, a timestamp that never goes back, CODEOWNERS for `vendor/`, the working-directory rule and clean offline builds (spec 042 R15, T15; spec 041 R14) |
| N42 | `Sink` calls carried no generation, so a late `locked` or old events could wipe or leak into a new unlock (N-A2, N-B4, N-C5, N-D3) | Medium | A generation on every `Sink` call and from `open`; apps drop older ones (specs 042, 040, 041, 056 R21) |
| N43 | A foreign exception in a callback panics the adapter thread, losing every later event (N-C6) | Medium | Each foreign call guarded (spec 040 R6) |
| N44 | Joining the adapter thread in `Drop` deadlocks or panics (measured) (N-C7) | Low | The sender taken out, no join (spec 040 R5) |
| N45 | A cfg on one constructor inside the export block fails to compile; the fixed-clock `Core` twins broke the release library (measured) (N-A3, N-C3, N-C4) | Medium | A separate cfg'd export block; the twins in the test source sets (spec 040 R5, R9) |
| N46 | Plain `cargo test` could not reach the feature-gated test code (N-A4) | Low | Tests with the features, plus a featureless check (specs 040 R12, 042 R14) |
| N47 | "Try again" called `network_changed`, which leaves `ProxyRefused` alone, cuts every socket, and does not exist on the desktop (N-A1, N-B7, N-C8, N-D15–N-D17) | Medium | `retry_now()` on the host, `Core` and the desktop (specs 042 R10, 040, 041 R4, R11, 056 R10) |
| N48 | "Opened before" was undefined and connects in progress escaped the merge (N-C9, N-D23) | Low | The start of the connect; connects in progress aborted (spec 042 R10) |
| N49 | What a probe aborted by the lock returns (N-A9, N-D25) | Low | `Locked` (spec 042 R11, T11, T12) |
| N50 | A lock with no device open could emit `locked` again (N-D12) | Low | It calls nothing (spec 042 R12) |
| N51 | Message bodies crossed three unbounded queues to apps that re-read anyway (N-B8) | Low | `HostEvent::Message` carries no body (specs 042, 040, 041, 056) |
| N52 | The host emits during `open`, before it returns (N-A7) | Low | "Until the next open begins" (specs 042 R5, 041 R7) |
| N53 | `rcgen` with `ring` needs a banned-crate wrapper (N-A6) | Low | Committed certificate fixtures (spec 042 T09) |
| N54 | The key share is set by the key-exchange group, and rustls shuffles extension order per connection (measured) (N-C10, N-C11) | Low | A fixed-share group wrapper; "the same handshake" defined as the same extension set (spec 042 R9, T09, Security) |
| N55 | The `nm` checks misread, false-matched and ran only on the bindings job's artefacts (measured) (N-B9, N-C12) | Low | `llvm-nm`, the exact symbol, a positive control, also in the app jobs (specs 040 R12, 051 R8, 052 R8) |
| N56 | Paused clocks need a current-thread runtime (measured) (N-C13) | Low | Stated (spec 042) |
| N57 | The adapter queue is unbounded (N-C14) | Low | A documented residual (spec 040) |
| N58 | The iOS fallback connection marks iOS to the server; VPN routing of native sockets unmeasured (N-B6) | Low | A residual; 042-R10 widened (spec 042) |
| N59 | `copy_message` took an untagged id, reopening N6 for copy (N-A5, N-B3, N-D21) | Medium | `copy_message(channel, kind, id)`, nothing copied when ambiguous (spec 053 R14; spec 041; spec 050 R4) |
| N60 | Where the desktop page's clear and reload run was unsaid; inside the `Sink` it blocks, outside it can land after the next unlock (N-D6) | Medium | After the host routine, under the lifecycle lock, bounded (spec 041 R17; spec 053 R21) |
| N61 | A reset's `FileIo` returned to a page its own lock had reloaded (N-D7) | Medium | `take_reset_outcome` (spec 041; spec 050) |
| N62 | The desktop lacked the commands N47 and D4 need (N-D16, N-D8) | Medium | `retry_now`, `connection_states` (spec 041 R4) |
| N63 | A Linux dialog left open across a reload made "Unlock" fail silently (N-D9) | Low | `DialogOpen` (spec 041; spec 050 R7) |
| N64 | Notification coalescing and the focus check were undefined or blocking (N-D19, N-D20) | Low | A set of (channel, peer); an atomic focus flag (spec 041 R7; spec 053 R13) |
| N65 | The desktop's `.cargo/config.toml` and offline Windows build were unlisted (N-A12, N-A14) | Low | Listed; 041 R14 cites 042 R15 (spec 041) |
| N66 | iOS grants about 30 s, not 120 s, and a lock started in the expiration handler gets none; a stale 053 R20 clause (N-D13, N-A13) | Medium | The shorter of the two, a timer-started lock, view models dropped first; the clause removed (spec 053 R8, R9, R20) |
| N67 | Android kills during a lock or a send were undocumented (N-D14) | Low | Residuals (spec 053 Security) |
| N68 | Under a newer app's settings, "Lock after" re-wrapped for a setting that is never saved (N-D26) | Low | Disabled then (spec 053 R7; spec 056 R15) |
| N69 | The QR image outlived a channel moved to `broken` (N-D27) | Low | Dropped when it leaves `channels()` (spec 041 R6) |
| N70 | Audit-log references for N15 and N17 (N-A15) | Low | Fixed |
| N71 | After a lock, an own row read "Not sent" and offered "Send again" while the server might already hold it (N-D1) | Medium | "Not confirmed yet" until the first `Subscribed` (spec 056 R8) |
| N72 | `Delivered` could overtake `SentView` (N-D2) | Low | Replace by `client_ref`, apply a seen `Delivered` (spec 056 R7) |
| N73 | Dropping overtaken re-reads livelocked a busy channel; unthrottled full re-reads at unlock (N-D4, N-D5) | Medium | Keep the read, re-apply later events; one coalesced read in flight (spec 056 R11) |
| N74 | Apps had no way to tell a late `locked` from a current one (N-B4, N-D3) | Medium | Generation filtering; the lock controller follows its own calls (specs 056 R21, 050–052 R2) |
| N75 | The Retrying text blamed a local Tor for any proxy fault (N-D18) | Low | A neutral text, "on this device" only for loopback (spec 056 R10) |
| N76 | The erase escape missed the fault after a successful open, and was offered for transient `Io` (N-A11, N-B5, N-D10, N-D11) | Medium | After a fault lock and for `Internal`, `Corrupt`, `UnsupportedVersion`; `Io` retries; cleared on background; the desktop `KeyLost` screen named (spec 056 R20; spec 050 R6) |
| N77 | A channel removed another way left its screen open (N-D27) | Low | Any `UnknownChannel` goes back to the list (spec 056) |
| N78 | A page mounted while unlocked had no connection states and showed Locked (N-D8) | Low | `connection_states()` after unlock and at mount; `status()` at mount (specs 056 R21, 050 R2) |
| N79 | Copy on position-keyed rows (N-B3) | Low | Hidden (spec 056 R8) |
| N80 | — | — | `DialogOpen`'s text (spec 050 R7) |
| N81 | Android ignored a network that came back; the iOS fallback could wait forever, reconnect later outside a proxy, or target channels outside any plan (N-D22, N-D24, N-B6, N-A8) | Low | `onLost` clears; 5 000 ms bound, cancels at lock and proxy change, `!needs_proxy` while no settings reset (specs 051 R4, 052 R4) |
| N82 | 056's acceptance and T03 missed its last requirements (N-A10) | Low | Fixed (spec 056) |
| N83 | — | — | See N55 (specs 051 R8, 052 R8) |
| N84 | — | — | See N61 (spec 050) |

Accepted without a question, recorded here: the Locked screen offers "Erase all data" only after a fault or a failed open whose reason is not transient (N76). A thief reaches it only after the device's own authentication, and erasing is then no more than uninstalling the app or deleting its folder, which that person could do anyway.


Round 3 (three passes, N-A, N-B and N-D, about 39 findings, 4 of them blockers, consolidated; no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| N85 | The generation filter sat in two layers that contradicted each other, and a filter on "the generation `open` returned" let through the queued calls of the generation just locked (N-A1, N-B8, N-D1, N-D2) | Medium | One filter per platform, `Core` and the bridge, dropping every call at or below a floor set when the owner's own lock starts; the host emits only `locked` after its increment (specs 040 R9, 041 R7, 042 R5, R12; 050–052 R2, 056 R21) |
| N86 | A fault lock left the phones' `LockController` believing it was unlocked, so "Unlock" did nothing (N-B2, N-D3) | Blocker | A current `locked` moves every owner to locked (specs 040 R9, 053 R9, 041 R17) |
| N87 | A fault lock skipped the desktop clear and reload, and its fault flag never reached the page (N-A3, N-B2, N-D2, N-D4) | Medium | The lock tail runs on a fault lock; `locked { fault }`; the notice kept for the next page (specs 041 R7, R17; 050 R2, R6) |
| N88 | `take_reset_outcome` returned `Locked` at mount, and could be read before the reset finished (N-A2, N-D7, N-D8) | Blocker | `take_lock_notice()`, allowed while locked and waiting on the lifecycle lock (spec 041 R9, R16, R17; spec 050) |
| N89 | The bounded reload could be held by a hung clear, an `onbeforeunload` dialog or a busy script, leaving the old page alive (N-B3, N-D6) | Medium | Navigate regardless, script dialogs suppressed, done at the new page's first command, the window recreated on timeout, `ReloadPending` until then; a reset always reloads (spec 041 R17; spec 050) |
| N90 | One bad frame from a server led straight to "Erase all data" (N-B1) | Medium | After a first fault only "Unlock"; the erase only when the fault recurs or an open fails for good (spec 056 R20) |
| N91 | A busy channel was re-read in full every second under the device lock (N-D10) | Blocker | Only the channel on screen, at most every max(1 000 ms, twice the last read); open question 056-R11 on a delta read (spec 056 R11, Limits) |
| N92 | "Not confirmed yet" never cleared when `Subscribed` came before the screen, or never came (N-D11) | Medium | `subscribed` in the app map and in `connection_states()`; channels that cannot subscribe show "Not sent" (specs 042, 040, 056 R8) |
| N93 | `retry_now` was synchronous against the async-only rule and had no rate bound (N-A4, N-B4, N-D12) | Low | Exempted; one effect per 5 000 ms; the button disabled until the next state (specs 040, 042 R10, 041 R11, 056 R10) |
| N94 | The Failed record survived an erase and kept a rejoined channel paused (N-D5) | Low | `Host::clear_failed()` at both resets (specs 042, 041 R16, 053 R23) |
| N95 | A fresh Windows machine without Windows Hello could never create its key (N-D14) | Medium | Availability checked on the first-run row (spec 053 R4) |
| N96 | The iOS fallback never ran at unlock, the case it exists for, and reached servers the host had stopped contacting (N-D16, N-B5) | Medium | Also at unlock and on entering `Retrying` over cellular; only channels `Connecting` or `Retrying` (spec 052 R4; spec 042 Security) |
| N97 | The rollback check on the vendored libsodium could be forged or bypassed; the zip hash was a placeholder (N-B6) | Low | The global signature verified; the last timestamp and the hash recorded in the spec; the lint fails with none (spec 042 R15, T15) |
| N98 | `SODIUM_LIB_DIR` and its siblings could bypass the vendored library (N-B7) | Low | Refused in configs and workflows; unset in the host and desktop legs (spec 042 R15) |
| N99 | Git for Windows would rewrite the vendored signatures to CRLF (N-D17) | Low | `.gitattributes` with `-text` (spec 042 R15) |
| N100 | Cargo launched from `pnpm` ran outside the workspace; step order and the bundler's downloads (N-D18) | Low | `cd src-tauri`; ordered steps; no bundler on the offline leg (specs 041 R5, R14, 050 R11) |
| N101 | `tauri` with no default features drops its runtime (N-D19) | Medium | The default features but `compression`, listed (spec 041 R2) |
| N102 | Windows test binaries may need an embedded manifest (N-D20) | Medium | Measured when slice (a) lands (spec 041 R14) |
| N103 | The host's Windows leg would build the server offline (N-D21) | Low | It builds nothing from the root workspace (spec 042 R14) |
| N104 | Copy by keyboard had no chosen row; position keys could move between rows (N-D13) | Low | The focused row; a stable rule (specs 050 R4, 053 R14) |
| N105 | Records and texts left over from round 2: `FfiReceived`, `FfiChannelState`, a swallowed Interface line, `Sent` in a test, "four files" beside `SHA256SUMS`, the `Locked` rule for non-`Result` methods, the plaintext sentence (N-A5–N-A10) | Low | Aligned (specs 040, 042) |

Round 4, two passes (N-A, N-D), final (about 23 findings, 2 of them blockers):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| N106 | The floor set at an owner's own lock dropped that lock's own `locked`, so the page never learnt of a lock and the phones' round trip could not pass (N-A1, N-D1) | Blocker | The owner emits its own `locked` at the start of its lock; the host's copy is dropped at the floor, a fault `locked` passes; the floor only rises (specs 040 R9, R15, 041 R7, R17, 053 R9) |
| N107 | The desktop's clear, navigate, script-dialog suppression, first-command detection and recreation fallback: destroying the one window quit the app, the recreated window lacked its handlers, an old page could mark the reload done, and WebView2's suppression needs `unsafe` (N-D2–N-D4, N-A5, N-A7) | Blocker | Simplified: the window is destroyed and rebuilt by the start-up builder at every lock and reset, with a `recreating` flag past the quit path; `ReloadPending` until the new page loads (spec 041 R17; spec 053 R20, R21; spec 050) |
| N108 | `clear_failed` returned `Locked` after the reset's own lock (N-A2, N-D5) | Medium | Allowed while locked (spec 040 R5) |
| N109 | A recurring fault could not be told from a first one, on the desktop after a reload and on the phones after a lock (N-A3, N-D6) | Medium | `Fault { recurring }`; a count outside the view models, reset only by a reset or a new process (specs 041, 050, 051, 052, 056 R20) |
| N110 | The iOS fallback's `networkChanged` cut every healthy connection at each unlock and each `Retrying` (N-A4, N-D10) | Medium | `retryNow` after those triggers; the unlock trigger only on cellular; nothing with no target (spec 052 R4) |
| N111 | Events already in the phone app's queue crossed the lock (N-D7) | Medium | The queue drained and discarded at the end of the lock, then the map cleared (specs 051 R2, 052 R2) |
| N112 | A `connection_states()` snapshot could overwrite newer events (N-D8) | Medium | Events after the call re-applied; `subscribed` only rises within an unlock (spec 056 R21) |
| N113 | "Try again" could stay disabled for good (N-A8, N-D9) | Low | 5 000 ms or the next state, whichever first (spec 056 R10) |
| N114 | Copy on an own row whose `server_id` repeats did nothing (N-A9) | Low | Own rows are always copied by `client_ref` (specs 053 R14, 050 R4, 056 R8) |
| N115 | The Windows first-run test needed a read before verification; `presence.none` outlived a Hello set up later (N-D11) | Low | "Holds no data" alone; the file removed when Hello is available (spec 053 R4) |
| N116 | Leftovers: `connection_states` missing from the locked-command list, `Sink::locked`'s duties, "the reset outcome", the floor "set" rather than raised, the re-read pacing's clock (N-A6, N-A10, N-A11, N-D12) | Low | Aligned (specs 041, 040, 056 R11) |

**Audit N stops here**, by diminishing returns: about 66, 66, 39 and 23 findings over four rounds, the last ones concentrated in the desktop lock tail, which round 4 simplified rather than patched. Open before implementation: 052-R10 (export compliance, a legal decision), 056-R11 (the cost of `messages()` on a channel of 10^5 rows), and the measurements that 041 names for slice (a) (Tauri's features, its CLI's working directory, the Windows test manifest).


Measurement of 042-R10, 2026-09-27, on the reviewer's iPhone 15 Pro Max with iOS 26, with a test app outside the repository (a Rust static library opening a std `TcpStream`, which is the BSD socket the host's `tokio` uses, and `NWConnection` for comparison, both fetching Cloudflare's `/cdn-cgi/trace`, signed with the GLAM SOFTWARE team's wildcard development profile at the reviewer's choice):

| State | Rust socket, first network use of the app | `NWConnection` |
| --- | --- | --- |
| Wi-Fi, a full-tunnel VPN on | out through `utun8`, the VPN | the same interface and public address |
| Wi-Fi, no VPN | out through `en0`, the Wi-Fi | the same |
| Wi-Fi off, three minutes locked, then unlocked | out through `pdp_ip0`, the cellular data (DNS 205 ms, against 6–14 ms before: the radio woke), the carrier's address | the same |
| Wi-Fi off, the VPN on | out through `utun7`, the VPN, with the VPN's exit address and not the carrier's | the same |

The unlock itself may wake the network, so the test cannot tell whether the Rust socket alone woke the radio; it shows the case the app lives in, since the app is always opened after an unlock. 042-R10 is closed: spec 052-ios-mvp R4 drops its data-free `NWConnection` fallback, and specs 040 R10 and 042 R3 their exception for it, together with the residual of 042's Security. A per-app VPN and Android were not measured.


## Audit M

**2026-09-26 — Audit M, review of the phase 5 draft specs 053, 054 and 055 before human review, in four independent passes (M-A: coherence and SDD conformance; M-B: adversarial security and privacy; M-C: technical viability, measured with ZXing 3.5.4, the `qrcode` crate, Core Image, Vision, the macOS Keychain, `security-framework`, the `windows` crate and `cargo deny`; M-D: end-to-end scenarios), in rounds.** The human reviewer decided five questions with the recommended option (M-Q5 in round 3):

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| M-Q1 | On Android, a system screen the app opens itself (file picker, share sheet, camera settings) stops the activity, so the lock on `ON_STOP` broke export, file import and sharing (M-A3, M-B8, M-C8, M-D1) | A bounded exception: while a system screen the app opened is in front, the app stays unlocked for at most 120 s; screen-off always locks; secrets are produced only after the return | Spec 053 R8; spec 054 R9, R10, R13 |
| M-Q2 | iOS cannot block a screenshot of the invitation QR or the seven words; it only reports one afterwards (M-B1, M-C13) | A documented residual; on `userDidTakeScreenshotNotification` the app hides the QR or words at once and warns that a screenshot is in Photos and, if it left the phone, to create a new channel | Spec 053 R12; spec 054 R7, R10, Security |
| M-Q3 | No client ever produces an invitation as text, so a desktop paste has no legitimate source but a third-party decoder or a photo, §12's first risk (M-B12) | The desktop imports by file only; paste is removed on every platform | Spec 054 R11, R13; decision Q6 narrowed |
| M-Q4 | An import joined and connected at once, so a planted QR led straight to an attacker's server, possibly under a look-alike name (M-B4) | A confirmation screen before an import commits: the suggested name (editable), the server host, the lifetime, a mark for a server new to this device, a warning for a name close to an existing channel's; a frame with more than one QR delivers nothing | Spec 054 R12, R15 |
| M-Q5 | The clipboard was cleared at lock, and leaving the app locks it, so a copied message could never be pasted in another app (round 3, M-D1) | Leaving the app does not clear it; it is cleared 60 s after the copy (the desktop timer; on Android at the next foreground once older); "Lock now", screen-off and a session lock clear it at once | Spec 053 R14 |

Round 1 (about 90 findings, 9 of them blockers, consolidated):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| M1 | The Android key never called `setUserAuthenticationRequired(true)`, so `K_db` unwrapped with no prompt (M-C1) | Blocker | Added (spec 053 R1, T01; §8 at acceptance) |
| M2 | Android read QRs through `BYTE_SEGMENTS`, and the desktop and iOS renderers mix segment kinds: about half the desktop invitations and a fifth of verification QRs could not be scanned (measured, M-C2, M-D2, M-A2) | Blocker | The scanner takes `Result.text`, printable ASCII, ≤ 700 characters; the desktop renders one byte segment (spec 041 R6 at acceptance); every renderer decoded by both readers (spec 054 R5, R12, T05, T12) |
| M3 | The lock on `ON_STOP` broke export, file import and sharing on Android, and the app's own dialogs locked the desktop (M-A3, M-A5, M-B8, M-C8, M-D1, M-D4) | Blocker | M-Q1's bounded exception; the export order; the share file deleted at the next unlock or start; dialogs and OS prompts do not count as unfocused (spec 053 R8; 054 R8, R9, R13) |
| M4 | A crash or cancel during an Android re-wrap could lose every file; the prompt count and the order with the setting were wrong (M-C7, M-D3, M-B10, M-A17) | Blocker | A generation byte and two aliases, a crash-safe order, the setting saved last, a check at every unlock (spec 053 R1, R7, T07, Limits) |
| M5 | iOS screenshots were said to be blocked (M-B1, M-C13) | Blocker | M-Q2 (spec 053 R12; 054 R7, R10, Security) |
| M6 | The grace counted from any device unlock on Android and from backgrounding on iOS (M-B2, M-C6, M-D8, M-A11) | Medium | An in-memory timestamp of the in-app prompt, one definition; `setUnlockedDeviceRequired` only from API 35 (spec 053 R1, R7, T07) |
| M7 | Locking left decrypted content in view models, visible behind the next prompt (M-B3) | Medium | A single `Locked` state that drops every view model's data first (spec 053 R21, T21) |
| M8 | Imports joined at once (M-B4); verification over the attacker's route (M-B5) | Medium | M-Q4's confirmation with a core preview (spec 054 R15, R17; 027 and 040 at acceptance); the in-person question and texts (spec 055 R9, R18, R19) |
| M9 | Compose dialogs escape `FLAG_SECURE`; the desktop can protect its window from capture (M-B6, M-B7) | Medium | Secrets on full screens, dialogs `SecureOn`; `contentProtected` (spec 053 R12; 054 R7, R10; 041 R8 at acceptance) |
| M10 | Autofill, personalised learning and Compose password fields (M-B9, M-B21, M-C9) | Medium | Excluded; `InterceptPlatformTextInput`; the `String` a residual (spec 053 R15; 054 R14) |
| M11 | The clipboard rules could not run (Android background reads, the lock aborting the desktop timer, `EXTRA_IS_SENSITIVE` from API 33; no desktop command) (M-B11, M-D18, M-A6, M-A7, M-C10, M-C18) | Medium | A detached desktop timer through `copy_message`; Android cleared at the next foreground or lock; `arboard`'s BSL-1.0 in spec 041 R2 at acceptance (spec 053 R14) |
| M12 | macOS data-protection items need a team-signed build (measured −34018); `security-framework` needs `OSX_10_15`; a cancel mapped to `KeychainUnavailable` (M-C3, M-C4, M-B23, M-A13) | Medium | Release builds refuse to start on −34018, debug builds may fall back behind a flag; `Cancelled`; 053-R3 closed (spec 053 R3, T03) |
| M13 | Notifications: `tauri-plugin-notification` brings `rand`; muted peers; the timeout's effect (M-C5, M-D11) | Medium | `notify-rust`; muted excluded; stated (spec 053 R13) |
| M14 | Session-lock signals on Linux; Windows Hello fallback reachable by "busy" (M-C11, M-D12, M-B19) | Medium | `LockedHint` and `Lock`; fallback only when Hello is absent or unconfigured; macOS and Windows signals an open question (spec 053 R4, R8) |
| M15 | No device credential, transient iOS failures read as `KeyLost`, mobile reset undefined, the KeyLost text (M-D6, M-C12, M-B25, M-D13, M-D15) | Medium | `Unavailable`, `Transient`, `Failed`; `reset()` with a convergent order; the text names old keys (spec 053 R5, R19, R23) |
| M16 | Platform logging had no rule (M-B18) | Low | Spec 053 R22 |
| M17 | Retiring unknown keys, `LabelInUse` without the §7 retire dialog, the stranger dead end (M-D9, M-D10, M-A8, M-B24) | Medium | Retire on every record; the third action; an unlabelled retired peer's text (spec 055 R7, R12, R15, R16, R18, R19) |
| M18 | Retire as social engineering; names imitating marks (M-B13, M-B14) | Low | The impostor warning; marks outside the name run (spec 055 R2, R15) |
| M19 | The verify flow's error mapping and label; the presentation inputs; the scanner's purpose (M-D14, M-D20, M-A20, M-D21, M-A9) | Medium | Scan first, shape check, label after; `TrustContext`; `purpose` (spec 054 R12; 055 R1, R10, R19) |
| M20 | Desktop paste had no legitimate source (M-B12) | Medium | M-Q3 (spec 054 R11, R13) |
| M21 | The words vs the call; the words and share sheets on background; payloads in verify mode not zeroed (M-D5, M-B15, M-B16, M-B22) | Low | Words first with an "I have told them" step; dropped on background; share-sheet exclusions; every payload zeroed (spec 054 R8–R10, R12) |
| M22 | Dependency allowlist and manifest checks underspecified (M-B17, M-D19, M-C15) | Low | Names only, `releaseRuntimeClasspath`, cargo-deny `[bans] allow`, Xcode references, the merged manifest (spec 053 R16, R17) |
| M23 | Restore gives an empty app, not `KeyLost`; "Lock now" shortcuts useless (M-D17, M-C17, M-D7, M-C14) | Low | Corrected; shortcuts dropped (spec 053 R7, R10, R11) |
| M24 | Interface, paths, names, Depends and Blocks, texts, amendment lists (M-A10, M-A12, M-A14–M-A16, M-A18, M-A19, M-A21–M-A24, M-C16, M-C19, M-C20, M-D16, M-D23) | Low | Aligned; open questions 053-R8, 053-R14 and 053-R17 to be measured (specs 053–055; 021 and 023 Blocks) |
| M25 | doc_lint read "257-byte" as a spec id in the pushed commit (M-A1) | Blocker | Fixed in 0883c6e |

Round 2 (about 45 findings, no blocker; no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| M26 | The 120 s exception and screen-off relied on callbacks that a frozen or suspended app does not get (M-B1, M-D3) | Medium | Checked at the return on a monotonic clock, before the first frame; the timer best effort; a residual for the frozen process (spec 053 R8, T08) |
| M27 | An open desktop dialog stopped the lock timer with no limit (M-B2) | Medium | Capped at 120 000 ms and lost when the dialog loses focus; the lock routine closes it (spec 053 R8) |
| M28 | The desktop clipboard reached Windows' cloud clipboard and history; `copy_message` kept plaintext; `arboard`'s defaults broke `cargo deny` and its threading rules (M-B3, M-B4, M-C3, M-C4, M-A6) | Medium | Exclusion flags on every OS; a hash, not the text; `default-features = false`; one clipboard task (spec 053 R14) |
| M29 | Saved instance state and scene storage could keep passwords and content outside the lock; the desktop page might ignore `locked` (M-B5, M-B6) | Medium | No saveable secret state; a restored process opens on `Locked`; the host reloads the web view (spec 053 R21; 041 R17 at acceptance) |
| M30 | The Android re-wrap check at unlock needed `K_db` after `Core.open` zeroed it, and ran outside the queue (M-D2, M-C6) | Medium | A non-secret grace file read before `Core.open`; the re-wrap in the queue; prompt counts per path (spec 053 R1, R7, R9) |
| M31 | Zeroing conflicted with preview → import → replace, and a refused or cancelled scan was never zeroed (M-A3, M-D1) | Medium | A fresh copy per core call; zeroed on every exit; the scanner's accept predicate zeroes what it refuses; 040 R7 and R9 amended at acceptance (spec 054 R12, R15, R17; 055 R19) |
| M32 | The scanner stopped after one payload while 055 needed it open; planted codes still won across frames (M-A4, M-B9, M-C7) | Medium | An accept predicate; three consecutive frames; two payloads in a session deliver nothing (spec 054 R12) |
| M33 | 055 claimed 041 was already amended; 054's list for 041 was incomplete (M-A1, M-A2, M-C5) | Medium | Acceptance-time amendments, complete: `verify_scanned` and `import_qr` out, `preview_file` in, one byte segment with `features = ["svg"]` (spec 054 R17; 055 R20) |
| M34 | The retire-and-rename offer needed a UI name match, and moved a name to an unverified key in one step (M-A5, M-B8) | Medium | Only after a verification, from `claims_name_of`; `LabelInUse` offers Verify first (spec 055 R15, R18, R19) |
| M35 | notify-rust posts as Finder or PowerShell and swizzles the bundle id (M-C1, M-D12) | Medium | `set_application` and `app_id`; the swizzle stated (spec 053 R13) |
| M36 | The in-person question offered a call for a QR (M-B7) | Low | "Is their phone in front of you?" (spec 055 R19) |
| M37 | A release could be built with the keychain fallback; the merged manifest's permissions were unchecked (M-B10, M-B11) | Low | `compile_error!`; an exact permission list (spec 053 R3, R17) |
| M38 | Grace edge, invalidated key vs no credential, reset crash, session signals (M-D8, M-D10, M-D11, M-C2, M-A7) | Low | Prompt on `UserNotAuthenticatedException`; `KeyLost` first; a tombstone; 053-R8 closed with the Linux session path (spec 053 R5, R8, R23) |
| M39 | The share file's deletion, iOS save to a file, the confirmation's name, `is_open` and onion cases, the words flow, desktop focus (M-A10, M-A13, M-D4–M-D7, M-D9, M-D14) | Low | Stated (spec 054 R8–R10, R15, R17) |
| M40 | Test fixtures, skill and §8/§10 amendment lists, file layout, Blocks, texts (M-A8, M-A9, M-A11, M-A12, M-D13, cosmetic) | Low | Aligned (specs 053–055; 022 and 053 Blocks) |

Round 3 (three passes, about 23 findings, no blocker):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| M41 | The retire-and-rename offer came from the stranger's claimed name and overwrote the label the user typed (M-B1, a hole M34 opened) | Medium | An explicit question naming both people; the typed label kept without a yes (spec 055 R18, R19) |
| M42 | The preview ran into `broken` and left the replace flow unreachable (M-A1) | Medium | The preview ignores `broken` and reports `replaces_broken`; the store error arises only after Join (spec 054 R15–R17) |
| M43 | The two-payload rule counted refused codes and lasted the whole session (M-A2, M-D3) | Medium | Only accepted payloads, in a 2 000 ms window; shape predicates for both purposes; the base64url check for `verify:` (spec 054 R12; 055 R19) |
| M44 | The Android re-wrap order mixed two paths; the grace before `Core.open` and on a fresh install were undefined (M-A3, M-A5, M-B2) | Medium | Two paths; the stricter grace before the open; 0 for a missing file; 60 at creation (spec 053 R7) |
| M45 | A copied message could never be pasted elsewhere; native selection bypassed `copy_message` (M-D1, M-D2) | Medium | M-Q5; text not selectable natively, the desktop page routes copy to `copy_message` (spec 053 R14; spec 050 to follow) |
| M46 | The desktop did not lock during system sleep; late Android screen-off; web storage survived the reload; the clipboard hash outlived the lock (M-B3–M-B6) | Low | Sleep and wall-clock checks; late `SCREEN_OFF` locks; `clear_all_browsing_data()`; a change counter first, forgotten after use (spec 053 R8, R14, R21) |
| M47 | Importing by file when the words are in another app; pasting into the password field (M-D4) | Low | A hint before the picker; paste allowed in the password field; the URI kept across the return only (spec 054 R11, R13) |
| M48 | Pre-verification never hinted at the old key; "Verify" undefined (M-D5, M-D6) | Low | A neutral hint on `label_collides`; "Verify" opens the word comparison or a choice with the scan (spec 055 R15, R18) |
| M49 | The OS unlock prompts ignored the focus rule; Windows notification clicks; iOS folder saves overwrote; the onion text; skill and 041 amendment wording; the dev banner (M-D7–M-D10, M-A6, M-A7, M-B note) | Low | Stated; 053-R13 open; `camera-compose`; `copy_message` a host command (specs 053, 054) |

Handed to spec 050-desktop-mvp: the page routes `copy` and Edit > Copy to `copy_message` and makes message text non-selectable; the Locked page never calls `unlock` without a user action (spec 053 R8, R14).

Round 4, two passes (M-A, M-D), final:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| M50 | A label typed on one card went to whatever phone was then scanned (M-A3, M-D1) | Medium | A card-bound scan compares the bytes with that peer's `fingerprint(pk).qr` and calls `verify` or nothing (spec 055 R15, R19) |
| M51 | The replace warning promised a confirmation that an `Io` entry never gives (M-A1) | Medium | `broken_reason: Option<StoreError>` in the preview, a text per reason (spec 054 R15, R17) |
| M52 | The unlock-time re-wrap only tightened, so a half-finished change never healed (M-A2, M-D3) | Medium | Re-wrapped to the grace file in both directions (spec 053 R7, T07) |
| M53 | A focused desktop that slept was not locked at wake on macOS and Windows (M-D2) | Medium | A heartbeat tick while unlocked comparing wall and monotonic clocks, checked before reconnecting; a logind delay inhibitor on Linux (spec 053 R8, T08) |
| M54 | The rename question asked to retire an already retired key; the clipboard's 60 s at quit and in the foreground (M-D4, M-D5) | Low | A plain rename question for a retired key; cleared at quit and by a foreground timer (spec 055 R18; 053 R14) |
| M55 | Cosmetic: a spec reference inside a UI string, a duplicate Limits row, the short-identifier pairing (M-A) | Low | Fixed (specs 053–055) |

**Audit M stops here**, by diminishing returns: about 90, 45, 23 and 8 findings over four rounds. Open to measure before implementation: 053-R4 (Windows Hello's placement), 053-R13 (a Windows notification click), 053-R14 (the macOS paste alert) and 053-R17 (iOS ATS for `ws://` onion).

## Phase 5 drafts

**2026-09-26 — Decisions taken before drafting the phase 5 specs.** Not an audit: the human reviewer decided Q1–Q4 with the recommended option before the specs were written, Q5–Q7 once the drafts of 053–055 raised them, and Q8–Q11 before the drafts of 050–052. Drafting choices follow as P rows.

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| Q1 | Whether to draft the six phase 5 specs at once or in two groups | Two groups: first the shared ones, 053-device-security, 054-qr-invite and 055-verify-ui, each group with its own audit; then the three platform UIs, 050, 051 and 052, which build on them | Specs 053–055 first |
| Q2 | On the desktop, reading the keychain asks the user for nothing, and spec 041 only has a native click to confirm an unlock | Every desktop unlock asks the operating system's user authentication where one exists: Touch ID or the account password on macOS, Windows Hello or the account PIN on Windows; Linux, with no standard equivalent, keeps the native confirmation of spec 041 | Spec 053; the desktop row of §8 "App lock" amended when 053 is accepted |
| Q3 | Which QR scanner on Android, given §8's "no third-party SDK" and F-Droid; whether the desktop uses a camera | ZXing, open source, on Android; the platform's own scanner on iOS; the desktop never uses a camera and imports by pasted text or file | Specs 054 and 055 |
| Q4 | Local notifications on mobile, where the app is disconnected whenever it is in the background | Notifications on the desktop only, with the fixed text "New messages", while the main window is not focused; none on Android and iOS, and §8's "Local notifications" row says so | Spec 053; §8 amended when 053 is accepted |
| Q5 | `setUserAuthenticationParameters`, which §8's Keystore parameters need, exists from Android 11 (API 30); on API 26–29 a second code path could not require the prompt at every open | `minSdk 30` | Spec 053 R20; spec 040 R11; §9 and the kotlin skill at acceptance |
| Q6 | Whether a phone may import an invitation by pasting its text, which passes through the clipboard | No: a phone imports by scanning or by opening the file; the desktop, with no camera, may paste | Spec 054 R11 |
| Q7 | Whether the phone may send the `.chatcfg` file through the system share sheet | Yes, through a temporary file deleted when the sheet closes, at lock and at the next start; the password is shown apart and never copied | Spec 054 R9 |
| Q8 | Whether Android and iOS open their server connections with the platform stacks (OkHttp, URLSession), as ADR 0040's consequences said, or with the Rust connection host of spec 041 | The Rust host, shared by the three clients through a spec of its own and uniffi: one audited implementation, no revocation fetch outside Tor, one SOCKS5 username per plan, the same headers and TLS fingerprint on every platform | ADR 0041 superseding 0040; new spec 042-connection-host; specs 040 and 041 amended; the kotlin and swift skills at acceptance |
| Q9 | Whether to draft 050, 051 and 052 one by one or together | Together, after the phase 4 rework of Q8, with one audit N | Specs 050–052 |
| Q10 | Where the shared host of Q8 takes its trusted roots from, given that iOS lets no app list its trust store and its one API that uses it is the platform verifier ADR 0040 refused | Mozilla's root list, compiled in through `webpki-roots`, on all three platforms: one behaviour, no network request, no root that a user, an employer or a program added; a network that intercepts TLS and a private authority cannot be reached, and a distrusted root stays until the next release | ADR 0041; spec 042 R9; spec 041 R2 and R12 amended |
| Q11 | Where the rules of the chat screens go, which are the same on the three platforms (channel list, channel screen, composer, connection state, settings, notices, help) | A shared spec, 056-chat-screens, with its own presentation fixture, as 053–055 are; 050, 051 and 052 keep how each platform places and wires them, its build, its CI and its publication | Spec 056; §10 phase 5 row |

Drafting choices, for the review of specs 053–055:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P1 | What `lock_timeout_seconds` means | The grace in which returning to the app skips the prompt, counted from the last prompt; going to the background always locks. On Android it is the Keystore's timeout, so changing it re-wraps `K_db`; on iOS the evaluated `LAContext` is kept that long; the desktop has none | Spec 053 R7 |
| P2 | How the desktop asks the OS (Q2) | macOS: the keychain entry becomes a data-protection item with user presence, through `security-framework`; Windows: `UserConsentVerifier` before the Credential Manager read, falling back to spec 041's confirmation when Windows Hello is unavailable; on both, the prompt replaces spec 041's `Unlock` confirmation, the first unlock of the process included | Spec 053 R3, R4; spec 041 R16 at acceptance |
| P3 | Desktop lock triggers | The window unfocused for the timeout, which also covers an OS session lock, and logind `Lock` on Linux | Spec 053 R8 |
| P4 | Where the wrapped key lives on mobile | `noBackupFilesDir/storage-key.wrap` on Android; an iOS Keychain item sealed to the Secure Enclave key | Spec 053 R1, R2 |
| P5 | iOS file protection and keyboards | `.complete`; custom keyboards refused | Spec 053 R11, R15 |
| P6 | How "no third-party SDK" is enforced | A dependency allowlist per client, checked in CI | Spec 053 R16 |
| P7 | Android cleartext | Allowed only for `.onion` hosts, which spec 027 R10's `ws://` onion route needs | Spec 053 R17 |
| P8 | Desktop notifications' rate | At most one every 60 s | Spec 053 R13 |
| P9 | How phones draw the invitation QR | ZXing `QRCodeWriter` on Android, `CIQRCodeGenerator` on iOS, byte mode, level M; the text's bytes zeroed once drawn | Spec 054 R5 |
| P10 | How long the invitation QR is shown | 60 s with a countdown, as §5 says, next to the invitation's own 10-minute expiry; hidden on background, lock or focus loss; spec 041 R6's image lives as long | Spec 054 R6; spec 041 R6 |
| P11 | The scanners | Android: CameraX (AOSP) with ZXing `core`, the payload from `BYTE_SEGMENTS`; iOS: `AVCaptureMetadataOutput` for `.qr`. A scan is at most 700 bytes, never opens a URL, keeps no frame; spec 055 reuses it | Spec 054 R12 |
| P12 | File types and URL schemes | None registered: the file is opened from inside the app | Spec 054 R13 |
| P13 | Creating a channel | No "create anyway" when the probe fails; lifetimes 1 h, 24 h, 7 days, 30 days, or custom | Spec 054 R1, R2 |
| P14 | One rendering of trust on three platforms | One pure presentation function per platform, tested against a shared fixture `clients/fixtures/trust_presentation.json`, which is UI data and not a frozen vector | Spec 055 R1, R21 |
| P15 | The desktop's own verification QR | Through spec 041's `qr` scheme, with a new command `export_verify_qr` | Spec 055 R17; spec 041 R4, R6 |
| P16 | Verifying on the desktop | By the 12 words only; pasting a peer's verification text is not the in-person check; a phone verifies the desktop by scanning its QR | Spec 055 R20 |
| P17 | Spec 014's partial-match rule | None: all 12 words in order, two buttons, nothing typed | Spec 055 R18 |
| P18 | Texts §7 does not fix | English sources written in spec 055; §7's own texts kept word for word | Spec 055 R3, R9–R19 |
| P19 | Retire and forget | Confirmed in the app, not natively; a script forging them is spec 041's residual | Spec 055 R15 |
| P20 | Muted peers | Their messages collapsed behind "Muted: show" | Spec 055 R7 |

Open, to be measured before implementation: a macOS data-protection Keychain item needs a signed build with an entitlement (053-R3); Windows Hello's prompt from a desktop process may open behind the window without `unsafe` (053-R4).

Drafting choices for the phase 4 rework of Q8 and Q10 (ADR 0041), for the review of specs 040, 041 and 042:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P21 | Where the shared host lives, given that the root `deny.toml` bans `rustls` and `ring` | `crates/host/`, a workspace of its own; `privatechat-ffi` leaves the root workspace for one of its own; the host's `deny.toml` is the base of the bindings' and the desktop's, and one doc-lint check covers the three workspaces' lints, profiles and libsodium pins | Spec 042 R1, R2; spec 040 R1; spec 041 R1, R2 |
| P22 | How the phones call a host that owns sockets and timers | uniffi async methods run on a runtime the `FfiHost` owns, events through a foreign `FfiSink`; `Core` keeps zeroing and becomes the one entry point, with no executor of its own, since the host keeps the order | Spec 040 R2, R5, R6, R9 |
| P23 | How the Kotlin and Swift vector tests pass a vector's `now` when no host method takes one | A `Clock` given to `Host::new`; `FixedClock` through an `internal` `Core` factory the apps cannot reach | Spec 042 R4; spec 040 R5, R9, R13 |
| P24 | How the desktop's wake check (spec 053 R8) runs before the shared host reconnects | `Sink::before_connect`, asked before every connect; the phones answer true | Spec 042 R9; spec 053 R8 |
| P25 | How a phone that changes network avoids 75 s of silence before reconnecting | `network_changed()`, which closes older sockets and cuts the backoff short, at most once per 10 s | Spec 042 R10; specs 051 and 052 say when |
| P26 | `tungstenite` depends on the `log` facade with no option to drop it (measured) | The facade stays; every crate that installs a logger is banned, and no source calls `set_logger` | Spec 042 R2, Security; spec 040 T01 |
| P27 | How to keep the references of spec 053 to 041 R15–R17 | 041 keeps those numbers; R10–R14 now hold the calls through the host, the network commands, no socket of its own, the panic hook and the CI job; R18, the exit test, becomes 042 R13 | Spec 041 |
| P28 | Whether the phones' boundary is tested beyond the vectors, now that events cross by callback | Kotlin and Swift each send one message through the server and see it delivered through `CoreListener` | Spec 040 R15 |
| P29 | Native sockets and App Transport Security, and Android's network security configuration | Neither governs them, so 053-R17 closes with no exception on either platform; whether an iOS native connect brings up cellular is 042-R10, to measure before 052 | Spec 053 R17; spec 042 open question |


Drafting choices for specs 050, 051, 052 and 056, for audit N:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P30 | Whether a URL in a message is a link | No link detection, no preview, no fetch: a tap or a preview reaches the network outside the host and tells a server the message was read | Spec 056 R2 |
| P31 | Where the user's name in a channel comes from, since the core keeps none globally | Asked at the first send in each channel, with a warning that the same name links channels; changed from the card for the next send | Spec 056 R12 |
| P32 | What the user does with an own message that expired unsent | "Send again", a new message with the same body; the old row stays "Not sent" | Spec 056 R8 |
| P33 | How the list shows new messages with no unread state in the core | A mark kept in memory since unlock, dropped at lock | Spec 056 R6 |
| P34 | Whether the phones confirm a proxy change, which only the desktop's native dialog did | Yes, in the app, naming what the change exposes; a loopback proxy needs none | Spec 056 R16 |
| P35 | Where "Erase all data" lives | In Settings on every platform, behind a destructive confirmation, through `reset_local_data` or `LockController.reset()` | Spec 056 R17 |
| P36 | Where the "help" that specs 053 and 041 cite lives | A Help screen with fixed sections, the first being §1's two lists word for word, checked against `docs/spec.md` by a test | Spec 056 R18 |
| P37 | Navigation without saved state (spec 053 R21) | Android: an in-memory `sealed interface Screen`, no navigation library; iOS: `NavigationStack` over an in-memory route enum, no restoration | Spec 051 R3; spec 052 R3 |
| P38 | Colours that mark an unknown key | Fixed theme colours at 4.5:1; Android's dynamic colour off, so a wallpaper cannot blur the secondary colour | Spec 051 R5; spec 052 R5; spec 050 R10 |
| P39 | iPad windows | One scene, so that one lock covers every window | Spec 052 R1 |
| P40 | When the phones call `networkChanged` | Android's default-network callback (so `ACCESS_NETWORK_STATE`); iOS's `NWPathMonitor`, with a data-free `NWConnection` only if 042-R10 finds that native connects do not bring up cellular, and never while a proxy is set | Spec 051 R4; spec 052 R4; spec 053 R17 |
| P41 | What "store publication process started" (§10) means | Store texts in the five languages under `fastlane/metadata`, "no data collected" answers, and the requests or accounts started, noted in the accepting pull request; the iOS export-compliance answer left to the human owner (052-R10) | Spec 051 R10; spec 052 R10 |
| P42 | Search, local deletion of one message, a tray icon, widgets | None in v1: each is one more copy of content or one more surface | Specs 050, 051, 052 and 056, Out of scope |

## Audit L

**2026-09-26 — Audit L, review of the phase 4 draft specs 040 and 041 and ADR 0039 before human review, in four independent passes (L-A: coherence and SDD conformance; L-B: adversarial security and privacy; L-C: technical viability, measured in throwaway projects with uniffi 0.32.2, Tauri 2.11.6, tauri-specta 2.0.0-rc.25, rustls 0.23.45, tokio-tungstenite 0.30.0 and keyring 4.2.0; L-D: end-to-end scenarios), repeated in rounds until they bring nothing new.** The human reviewer decided four questions with the recommended option:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| L-Q1 | `rustls-platform-verifier` lets macOS and Windows fetch OCSP, CRLs and intermediates on their own, outside the SOCKS5 proxy, which tells the network and the CA which server a Tor user talks to (L-B1, L-C7, L-D11) | Certificates are checked by `rustls`'s WebPKI verifier over the OS roots (`rustls-native-certs`), with no revocation fetch, with or without a proxy | Spec 041 R12, Security, T12; ADR 0039 |
| L-Q2 | `export_qr` handed the invitation text, which holds `K_ch`, to the web view, so an injected script could export every channel (L-B2, L-A4) | The Rust side renders the QR as an SVG on the `qr` scheme, which the page can show but no script can read | Spec 041 R6, R8, Security, T06 |
| L-Q3 | `tungstenite` needs `sha1` and `rand`, and Tauri needs `getrandom`, all banned by AGENTS 2 (L-A2, L-C1, L-B20) | Allowed in the desktop workspace as named wrappers: RFC 6455 mechanics, never a key or a message | Spec 041 R2, R3; ADR 0039 |
| L-Q4 | An injected script could erase the local data or change the proxy with one command (L-B3) | Both ask for a native confirmation drawn by the Rust side | Spec 041 R9, R16, T16 |

Round 1:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L1 | The events inside `Sent` and `regenerate_identity`'s result bypassed the host: a `Reconnect` after an own-key alert was never acted on and the retirement never left (L-A3, L-D1) | Blocker | The host takes the events out of every result; `send` returns `Sent` without them, `regenerate_identity` nothing (spec 041 R7, Interface, T07) |
| L2 | The CSP had no `connect-src` for Tauri's IPC scheme, so every invoke fell back to JSON `postMessage` and the password crossed as JSON (L-C3, L-B13) | Blocker | `connect-src ipc: http://ipc.localhost` (spec 041 R8, T08) |
| L3 | The measured graph brings `sha1`, `rand`, `chacha20`, three `getrandom`, `sha2`, `png`/`miniz_oxide`, `brotli` and the Secret Service crypto; `ring` also sits under `rustls-webpki`; brotli and the PNG decoder run at run time (L-A2, L-C1) | Blocker | The measured wrapper list; `tauri` without `compression`, `brotli` banned; AGENTS 24 amended at acceptance (spec 041 R2, R3; ADR 0039) |
| L4 | `tauri-specta` has no stable release for Tauri 2, cannot type `Request`/`Response` commands and refuses `u64` (L-C2) | Blocker | Exact `rc` pin; raw commands outside specta with hand-written wrappers; `JsU64` saturating newtype; mirror types in `wire.rs` (spec 041 R5, R6) |
| L5 | `generated.ts` was committed, against AGENTS 16 (L-A1, L-C11) | Medium | Generated at build and in CI, git-ignored (spec 041 R5, T05) |
| L6 | Drains from different calls could reach the socket out of order, and an `ack` of #6 before #5 lost #5 (L-D2) | Medium | One ordered writer queue per plan, filled in the same lock hold as the call (spec 041 R10, T10) |
| L7 | A server that stopped reading froze commands and `lock` (L-B7) | Medium | No command waits on a write; 256-frame queue; a 30 000 ms write deadline (spec 041 R10, R12, R17) |
| L8 | `lock` did not wait for tasks, so events followed `locked` and a new `Device` could reuse an old plan id; double `unlock` undefined (L-D3, L-B11) | Medium | Unlock generations; `lock` aborts and awaits every task and call, `locked` last; `unlock` while unlocked is `Ok` (spec 041 R10, R16, R17, T10, T16, T17) |
| L9 | First-run races between two instances, a read-back with no rule, and a keychain entry planted before the first run (L-B5, L-B6, L-D4, L-D5) | Medium | An instance lock outside the data directory; the read-back must equal the drawn key; an entry with no data is replaced; "holds data" defined (spec 041 R15, R16, T15, T16) |
| L10 | `reset_local_data` while unlocked, or deleting the entry before the directory, could leave data with no key (L-D6) | Medium | Lock first, delete the directory, then the web view directory, then the entry; `FileIo` keeps the entry (spec 041 R16) |
| L11 | The file dialog had no cancel, size, retry or `replace_broken` path (L-D9, L-B19) | Medium | `choose_chatcfg` reads a regular file of ≤ 1 085 B into one pending file; `Cancelled` and `FileIo`; `x-replace-broken` header (spec 041 R4–R6, T06) |
| L12 | Tauri's request buffer cannot be zeroed without `unsafe` (L-B15, L-C4) | Medium | The command's copy is `Zeroizing`; Tauri's buffer a documented residual (spec 041 R6) |
| L13 | `Fingerprint` could not be both JSON and a raw response (L-A6, L-C16, L-D13) | Low | Its `qr` crosses as a string, public (spec 041 R5) |
| L14 | Without an app manifest Tauri allows every registered command, and the capability file granted dialogs and allowed `core:default` (L-C10, L-A5, L-B14) | Medium | `AppManifest::commands` in `build.rs`; no dialog permission, no `core:default` (spec 041 R8, T08) |
| L15 | Navigation, forms and `<base>` were not covered by the CSP; the asset protocol was open (L-B4, L-B13) | Medium | `form-action`, `base-uri`, `frame-ancestors` `'none'`; navigation handler; new windows refused; asset protocol off (spec 041 R8) |
| L16 | The desktop workspace lost the root release profile, inherited the root `clippy.toml` (which forbids its clock), and could resolve another libsodium; only `[bans] deny` was copied (L-A8, L-A9, L-C8, L-C9, L-C15) | Medium | Same profile; its own `clippy.toml`; the same `libsodium-sys-stable` in both locks; `[bans.build]`, `[sources]`, `[advisories]`, `[licenses]` copied; `[graph] targets` (spec 041 R1, R2, T01, T02) |
| L17 | The connection states were undefined (`server_full` never ends; `needs_proxy` channels are in no plan) (L-A14, L-A15, L-D12) | Medium | Each state's start and end; `needs_proxy` read from `ChannelInfo`; `proxy_refused` added (spec 041 R7, R13) |
| L18 | A permissive SOCKS5 client would accept "no authentication" and merge circuits (L-B12, L-D15) | Low | Only method `0x02`, strict status and reply parsing, `proxy_refused` (spec 041 R12, T12) |
| L19 | A healthy onion server failed the 30 s connect bound on a first rendezvous (L-D16) | Low | 60 000 ms through a proxy to `.onion` (spec 041 R12, T12) |
| L20 | The exit test could not start the server (two `:0` on one address), knew no port and had no time bound; it named spec 034 but used 035 (L-D10, L-A7) | Medium | `[::1]:0` for the onion listener, ports from the start line, `PRIVATECHAT_SERVER_BIN`, 120 s; §10 wording names 035 and the two hosts (spec 041 R18; 040 R14) |
| L21 | Panic messages could cross uniffi into crash reports, and into stderr on the desktop (L-B8) | Medium | A `catch_unwind` guard and a silent panic hook (spec 040 R4, T04; 041 R10) |
| L22 | R9 asked to zero the array `generateStorageKey` returns, the key itself (L-B10) | Medium | Removed; T09 checks two different non-zero keys (spec 040 R9, T09) |
| L23 | One thread per `Core` let a new `open` overtake the old `close`; Kotlin's `close` shut the dispatcher, so later calls were cancelled, not `Closed` (L-D7, L-D8) | Medium | One executor per process, never closed (spec 040 R9, T09) |
| L24 | Kotlin typealiases hide nested sealed subclasses, so the apps could not match events without the generated module (L-C5) | Medium | No typealiases; the use check forbids `FfiDevice` and the free functions by name (spec 040 R9, R10, T10) |
| L25 | `wildcard_enum_match_arm` misses a `_` that covers one variant (L-C6) | Medium | `match_wildcard_for_single_variants` denied too (spec 040 R3; 041 R1) |
| L26 | A `--workspace` build unified uniffi's `cli` feature into the shipped library (L-C13) | Low | The bindgen crate is a workspace of its own; builds use `-p` (spec 040 R1, R11, T01) |
| L27 | Swift receives `Data`, not `[UInt8]`; the swift skill forbids GCD and names SwiftLint and SwiftFormat (L-C14, L-A12, L-B16) | Medium | `actor Core` over one `DispatchSerialQueue` executor, `inout Data` with `resetBytes`; the swift skill and AGENTS 20 amended at acceptance; §8 says `Data`; the copies listed as residuals (spec 040 R9, R12, Security) |
| L28 | `SODIUM_USE_PKG_CONFIG` and `SODIUM_SHARED` could also link a system libsodium (L-B20) | Low | All three variables unset and checked (spec 040 R11, T11) |
| L29 | The vector rules of R13 were not exact (which call, `now`, `info.id`, `fingerprint_reference`, `short`, the label, a `hello` without `event`) (L-A19, L-D14) | Low | Each made exact; spec 028 amended so that every `hello` vector carries `event` (spec 040 R13, R14; 028 Vectors) |
| L30 | Plain key arrays outside `crypto` against AGENTS 5 (L-A11) | Medium | AGENTS 5 names the caller-owned arrays at acceptance (spec 040 R8, T14) |
| L31 | Test names that `check_requirements` cannot see (040 T09, T10, T12; T08 in 027's name space) (L-A13, L-A16, L-A17) | Low | Renamed (spec 040 T08–T12; 027 Interface) |
| L32 | The skills, §8 and CONTRIBUTING had drifted from 041 (L-A23) | Low | Amended at acceptance (spec 041 R3, R18) |
| L33 | Missing and one-way `Depends on` and `Blocks` edges (L-A24) | Low | Specs 010, 011, 014, 020, 028, 030, 033 and 035 list 040 or 041; 040 and 041 list 020, 030 and 033 |
| L34 | Smaller fixes: R2's `ClientRef` (L-A18), the four host commands of R4 (L-A20), the probe's `BadPayload` (L-A22), the tick count of T11 (L-C17), the reason for `Display` (L-C18), the crate features (L-C19), the Windows entry's persistence (L-B17, L-D17), the web view's temporary directory (L-B18), the `tempfile` comment (L-A25, L-C13) | Low | Specs 040 R2, R4, R1; 041 R4, R8, R11, R12, R14, R16, T11 |

Not taken: jitter on the backoff and a random delay before the first connect (L-B9). The plans of one device share a server only when a plan's channel limit splits them, and a random wait of up to 30 s at every unlock costs every user for that case; it is a documented residual (spec 041 Security).

Round 2. The human reviewer decided two more questions with the recommended option:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| L-Q5 | An actor on a custom serial executor, which the Swift layer needs to run every call in order, exists only from iOS 17; the spec said iOS 16 (L-A2, L-C8, L-D7) | iOS 17 is the floor; `Core` is isolated to a `CoreActor` global actor over one `DispatchSerialQueue`, static calls included | Spec 040 R9, R14, Interface, T09; §9 and the swift skill at acceptance |
| L-Q6 | An injected script could still accept default settings without the previous proxy, remove a broken channel or replace one, which spec 027 puts behind destructive confirmations the web view draws (L-B1, L-D6) | Those three go through the native confirmation too; leaving a channel stays an ordinary action, a documented residual | Spec 041 R16, Security, T16 |

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L35 | ADR 0039, accepted and pushed, was edited in place against spec 002 R4 (L-A1) | Medium | ADR 0039 restored and `superseded by 0040`; ADR 0040 restates it with the verifier and crate list of L-Q1 and L-Q3; spec 041, the ADR index and §3 point to 0040 |
| L36 | Measured again, the wrapper list was wrong in five places, two bans it named were not in the root list, the copied `[advisories]` and `[bans.build]` failed on the Tauri stack, and the path dependencies were wildcards (L-C1–L-C5) | Blocker | The corrected wrappers; `png`, `native-tls` and `webpki-roots` added as desktop bans; seven advisory ignores; the WebView2 loader bypass; `allow-wildcard-paths`; the doc-lint check accepts exactly these differences (spec 041 R1, R2, T02) |
| L37 | The writer queue outlived its socket, so an old `subscribe` went out on the new socket, got `bad_auth` and refused the channel (L-D1) | Blocker | Frames carry their socket number; the queue is emptied with `on_disconnect` (spec 041 R10, T10) |
| L38 | `lock` aborted the tasks before waiting for calls in flight, which then started new ones (L-D2) | Blocker | `lock` raises the generation first, then waits, stops the tick, aborts, flushes (spec 041 R17, T17) |
| L39 | The keychain entry did not depend on the data directory, so an install at another path deleted the real key (L-D4, L-B6) | Medium | User `storage-key:` followed by the data directory's path (spec 041 R16, T16) |
| L40 | `Path::exists` reads an I/O error as "no data", which would draw a new key (L-B5, L-D5) | Medium | `try_exists` and `read_dir`, any other error `FileIo` with the keychain untouched; `try_lock` errors defined and retried (spec 041 R15, T15) |
| L41 | Native dialogs could be accepted by a stray Return, repeated until accepted, and showed a proxy the script chose (L-B2) | Medium | Cancel as default, one at a time, a 60 s silence after a decline, host-composed text (spec 041 R9, T09) |
| L42 | Web permission requests (screen capture, clipboard read, camera) were never denied (L-B4) | Medium | A deny-all permission handler per engine and a `Permissions-Policy` header (spec 041 R8, T08) |
| L43 | keyring 4 cannot set Windows persistence; only `keyring-core` with the `Local` modifier can (L-C7) | Medium | `keyring-core`'s `new_with_modifiers` on Windows; a Windows-runner test (spec 041 R16, T16) |
| L44 | The exit test's own `PRIVATECHAT_` variable stopped the server; `[::1]` may be absent; the start line had no field names (L-D3, L-D9) | Medium | `DESKTOP_TEST_SERVER_BIN`, `env_clear`, a probed port on 127.0.0.1; spec 035 R4 names `listen_port` and `onion_port` (spec 041 R18; 035 R4) |
| L45 | A cancelled Kotlin caller lost the events of a call that had run (L-D8) | Medium | `withContext(NonCancellable + dispatcher)` (spec 040 R9, T09) |
| L46 | `init` as a name broke the use check and a Swift twin, and the silent hook depended on the app calling it (L-A4, L-B8) | Medium | The export is `core_init`, called by `Core` itself; the guard installs the hook once; `Drop` guarded; `close` recovers a poisoned lock (spec 040 R2, R4, R6, R9, R10, T04, T10) |
| L47 | The invitation text holds `K_ch` but was not zeroed or counted as a secret (L-A5, L-B10) | Medium | `import_qr` zeroes it on both sides; six crossings listed; the desktop QR text and SVG in `Zeroizing`, served `no-store` (spec 040 R7, R9, Security; 041 R6) |
| L48 | SwiftPM cannot reach sources outside its package; build output dirtied the tree; the README was stale (L-A3, L-A8) | Medium | Swift output in `bindings/uniffi/swift/Generated/`; the ignore entries; the README rewritten (spec 040 R11) |
| L49 | uniffi's `tempfile` path is a runtime dependency, not a proc macro, so T01 as written failed (L-C6) | Medium | The path named; T01 checks where they sit and that `nm` finds none (spec 040 R1, T01) |
| L50 | Two 011 vectors had no record to import (L-A6) | Medium | Spec 011 amended: they carry their record; record-only negatives are encoded too (spec 040 R13, R14; 011 Vectors) |
| L51 | Blocking dialogs called on the main thread freeze the app (L-C11) | Low | Dialog commands `async`, `Dialogs` inside `spawn_blocking` (spec 041 R4, R9, T04) |
| L52 | Sockets the host closed itself were not reopened by R13's wording (L-A11) | Low | Any close but the stop rules and `lock` reopens (spec 041 R13, T13) |
| L53 | A panicking plan task left its plan dead (L-B8) | Low | Handled as a closed socket (spec 041 R10, T10) |
| L54 | T12 asserted a verifier type that rustls does not expose (L-C9) | Low | Tested by behaviour: a leaf with local CRL, OCSP and AIA addresses, which see no connection (spec 041 T12) |
| L55 | The SOCKS5 `VER`, sub-negotiation and `ATYP` errors were unstated (L-B, closing note) | Low | Each defined (spec 041 R12, T12) |
| L56 | The web view directory is ignored by WKWebView and WebKitGTK when incognito and locked by WebView2 at quit (L-C10, L-D11) | Low | Best-effort deletion, leftovers removed at the next start (spec 041 R8, R16) |
| L57 | `lock` during an `unlock`, and a second instance after the first quits (L-D10) | Low | `lock` waits for `unlock`; `unlock` retries the instance lock; keychain calls in `spawn_blocking` (spec 041 R15, R16) |
| L58 | Time Machine keeps history past its TTL (L-B11) | Low | The backup exclusion attribute on macOS (spec 041 R15, T15) |
| L59 | The honest list of what an injected script can do, the QR side channels, the roots that `rustls-native-certs` trusts (L-B3, L-B7, L-B9) | Low | Documented residuals; a per-engine check of the QR on Windows and Linux in the acceptance criterion (spec 041 Security, Acceptance criterion) |
| L60 | The amendment lists at acceptance missed AGENTS 2 and 20, §9's "Protocol tests" and "Mobile bindings", `bindings/README.md`, the skill's CSP and raw wrappers (L-A7, L-A9) | Low | Listed (spec 040 R14, T14; 041 R3, T03) |
| L61 | `Host`'s Interface lacked the confirming, file and raw-body methods and the paths; the test seam of 040 was unnamed; Kotlin test names not in snake case; no pending file read as `BadConfig` (L-A10, L-A12, L-D12) | Low | Named (spec 041 Interface; 040 R1, R5, Interface, T09, T13; 041 R6) |

Not taken: a key-check value in the data directory, so that a replaced keychain entry reads as `KeyLost` rather than `Corrupt` (L-B6). Binding the entry to its path (L39) removes the case that caused it; what is left is a same-user process that rewrites the entry, which §8 already leaves out of scope, and the check needs a new core function. It is a documented residual (spec 041 Security). Showing the QR in a second, script-free window (L-B3) is left to spec 054-qr-invite, since the canvas and fetch paths are closed and measured on macOS.

Round 3. `cargo deny check` is green with exactly the differences of spec 041 R2 (measured). The human reviewer decided two more questions with the recommended option:

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| L-Q7 | Tauri has no hook to deny web permissions; on macOS and Windows one needs `unsafe`, which spec 041 R1 forbids (L-C2, L-B9) | Per engine, with no `unsafe`: a WebKitGTK handler on Linux, no camera or microphone usage description on macOS, the `Permissions-Policy` header and no clipboard access on Windows, the WebView2 prompt a documented residual | Spec 041 R8, Security, T08 |
| L-Q8 | Reading the keychain asks the user for nothing, so a script that outlives an automatic lock can unlock at once (L-B3) | Every unlock after a lock asks a native confirmation; the first of the process does not | Spec 041 R16, Security, T16 |

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L62 | The replace confirmation could not name the entry, since only the core reads the invitation's `channel_id` (L-A1, L-B2, L-D4) | Medium | Two steps: the host calls with `replace_broken = false`, and only on `Corrupt` or `UnsupportedVersion` asks with fixed text and calls again; the header is gone (spec 041 R6, R16, Interface, T06) |
| L63 | `acknowledge_settings(true)` was unconfirmed once the flag cleared, and an `Io` reset's dialog promised "no proxy" before a re-read (L-A2, L-D3) | Medium | `ReplaceNewerSettings` whenever a newer file stands; the `Io` text says the file is read again (spec 041 R16, T16) |
| L64 | Whether a dialog holds the lock, and what a yes after `lock` does, was unstated (L-B1, L-D5) | Medium | Dialogs run with no lock and never count for `lock`; a yes re-checks the generation and the target (spec 041 R9, T09) |
| L65 | Script-chosen text could reach a dialog through `remove_broken`'s name (L-B2) | Medium | The name is looked up in `broken` first; unknown → `UnknownChannel`, no dialog; shown by `channel_name` or a fixed phrase (spec 041 R9) |
| L66 | A blocking closure queued before `lock` could run on the next `Device`, and a `std` guard cannot be held across `.await` (L-D1) | Medium | Every closure checks its generation under the lock; `lock` awaits with the lock released, then calls `on_disconnect` in one hold (spec 041 R10, R17, T10) |
| L67 | `reset_local_data` and `unlock` could interleave and lose a new key; the wait rules were circular (L-D2) | Medium | One FIFO async mutex serialises `unlock`, `lock` and reset (spec 041 R15, T15) |
| L68 | The path string of the keychain user differs for one directory reached by a symlink (L-B5, L-D6) | Medium | `fs::canonicalize`; a moved directory is a documented residual; the 513-character Windows limit (spec 041 R16, T16, Limits) |
| L69 | `keyring-core` has no default store until `keyring` sets it lazily, and the modifier is Windows-only (L-C1) | Medium | `store_status()` first; `keyring-core` pinned to `keyring`'s version; the modifier under `cfg(windows)` (spec 041 R16) |
| L70 | The round-2 Kotlin fix still lost the result: `withContext` returns to a cancelled caller with prompt cancellation (L-B4) | Medium | Nested `withContext(NonCancellable) { withContext(dispatcher) { … } }` (spec 040 R9, T09) |
| L71 | Calls from unrelated Swift tasks reached the executor out of order in 12 % of pairs (L-C5) | Medium | The guarantee is for calls made in sequence or from one actor; T09 uses the main actor (spec 040 R9, T09) |
| L72 | The exit test's crate was binary-only, so `tests/` could not reach the host (L-A4) | Medium | A library `privatechat_desktop`; the in-memory store under `test-support` (spec 041 R1, Interface) |
| L73 | Keychain reads were plain vectors, and the drawn key's fate on a mismatch unstated (L-A5) | Medium | `Zeroizing` reads; the drawn array to `from_bytes` or zeroed; AGENTS 5 names the buffer (spec 041 R16; 040 R14) |
| L74 | `privatechat-store` has no `test-support` feature (L-A3) | Medium | Only the core's (spec 040 R1) |
| L75 | The use check flagged the `Core.` twins (L-A8) | Low | Qualified matches defined; passing fixtures (spec 040 R10, T10) |
| L76 | `AckOutcome` and `Frame` were not excepted in R2 (L-A6); the "never a record field" sentence (L-A7) | Low | Excepted; reworded (spec 040 R2, Security) |
| L77 | No default-button setter exists in the dialog plugin (L-C4) | Low | `OkCancelCustom(<safe>, <action>)`, only `Custom(<action>)` accepts; a Linux manual check (spec 041 R9, Acceptance criterion) |
| L78 | The 60 s silence looked like a decline (L-B6, L-D8) | Low | `Suppressed { retry_after_ms }` (spec 041 R5, R9, T09) |
| L79 | `probe_server` had no concurrency bound (L-B7) | Low | One at a time; the LAN probe listed as a residual (spec 041 R14, Security, T14) |
| L80 | Launcher variables could re-enable WebView2 debugging or a persistent profile (L-B8) | Low | `WEBVIEW2_*` and `WEBKIT_INSPECTOR*` refused at start; hook first in `main`; no log subscriber (spec 041 R8, T08) |
| L81 | Temporary directories already read as excluded by `tmutil`; `xattr` does not build on Windows without defaults (L-C6, L-C7) | Low | The exact value, compared by bytes; `xattr` macOS-only (spec 041 R15, T15) |
| L82 | Windows lacks the signals the server needs, and `env_clear` drops `SystemRoot` (L-D7) | Low | The exit test on Linux and macOS; the Windows leg without T18 (spec 041 R18) |
| L83 | Amendment lists missed the §9 reason, the swift skill's `[UInt8]`, and §8 "Backup exclusion" (L-A10) | Low | Listed (spec 040 R14; 041 R3) |
| L84 | Undefined Interface names, the Limits row for the keychain, `disallowed-types`, the `on_frame` comment, `defaultServerUrl` (L-A cosmetic) | Low | Fixed (specs 040, 041) |

Round 4 (no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L85 | `tauri-plugin-dialog` maps rfd's `Cancel` to the second label, so with the action label second, Esc or the close button on Windows and Linux ran the destructive action (L-C1) | Blocker | Confirmations call `rfd` directly, with the gtk3 and common-controls-v6 backends; only rfd's `Custom(<action>)` accepts; a test maps each backend's dismissal (spec 041 R9, Interface, T09) |
| L86 | The FIFO mutex held across the reset and unlock dialogs let a script hold off `lock` and quit indefinitely, against R9 (L-A1, L-B1, L-D1) | Medium | The mutex is never held across a dialog; unlock and reset ask first and re-check under it (spec 041 R9, R15, T09) |
| L87 | Reset calling `lock` inside the non-reentrant mutex deadlocked as written (L-A1, L-D2) | Medium | The lock steps are one routine run with the mutex held; reset runs it inside its hold (spec 041 R15, R17) |
| L88 | Quitting during a dialog could hang the main thread (L-D3) | Medium | Close and exit are refused, the app locks in a task and then exits (spec 041 R17, T17) |
| L89 | `acknowledge_settings(true)` after an `Io` re-read that finds a newer file replaced it behind the weaker dialog; two dialogs could apply (L-A2, L-D4) | Medium | `replace_newer` passed only after `ReplaceNewerSettings`, which alone is shown when both apply (spec 041 R16, T16) |
| L90 | The broken-channel dialogs dropped spec 027 R3's text for `UnsupportedVersion` (L-A3) | Medium | The variants carry the reason and use 027 R3's texts (spec 041 R9, R16, Interface) |
| L91 | The second step of a file import could use a newly chosen file, and the kept body outlived `lock` (L-A4, L-B2, L-D6) | Low | One host-owned `Zeroizing` slot with both copies, emptied by `lock` (spec 041 R6, R17, T17) |
| L92 | A poisoned lock outlived `lock` and `unlock` (L-A5) | Low | `lock` clears the poison after dropping the `Device` (spec 041 R10, T17) |
| L93 | The dialog texts had no localisation source; T16 touched the real keystore (L-A6) | Low | `src-tauri/strings/` in the OS locale; the Windows persistence check moved to the non-automatable criteria (spec 041 R9, Acceptance criterion) |
| L94 | A script can pick the moment and argument of a confirmation, and keep a kind suppressed (L-B3) | Low | Per-kind button labels; stated as residuals (spec 041 R9, Security) |
| L95 | WebKitGTK emits no camera request by default, and the macOS bundle must name no usage description at all (L-C2, L-B4) | Low | T08 uses geolocation and notification requests in the app-built window; no `NS*UsageDescription` (spec 041 R8, T08) |
| L96 | WKWebView's "Paste" callout after a click (L-B5); registry and `defaults` switches outside the environment (L-B6) | Low | Residuals; a manual check on macOS (spec 041 R8, Security, Acceptance criterion) |
| L97 | "First unlock of the process" was undefined; commands while locked could open dialogs (L-B7, L-D5) | Low | Defined as "no `Device` opened yet"; already unlocked → `Ok` first; locked commands return `Locked` before any dialog (spec 041 R9, R16, T09) |
| L98 | An `open` from an unrelated task could overtake a queued `close` on mobile (L-D7) | Low | Ordered only when the caller awaited the `close`; spec 053 serialises (spec 040 R9) |
| L99 | Cosmetic: `leave` through `call` could not drop the QR; `Cancelled` omitted a busy slot; the use check on substrings; the Swift twin's `throws`; an already-cancelled Kotlin caller still runs (L-A cosmetic, L-C3) | Low | Fixed (specs 040 R9, R10, Interface; 041 R5, Interface) |

Round 5 (no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L100 | A synchronous rfd dialog run on the main thread stops the event loop on macOS (measured), and by rfd's source deadlocks on Linux, so no event, `locked` or close request was handled while a confirmation was open (L-C1) | Blocker | Async rfd on a `tokio` task on macOS and Windows, blocking rfd inside `spawn_blocking` on Linux; never on the main thread; a Linux check in the acceptance criterion (spec 041 R9, T09) |
| L101 | `prevent_exit` then `exit(0)` loops (measured); the macOS Quit item is `terminate:` and skips `ExitRequested` (L-C2, L-C3, L-D2) | Medium | A "quitting" flag; a custom Quit item; `RunEvent::Exit` drops the `Device` best effort, a residual (spec 041 R17, Security, T17) |
| L102 | A yes answered after the quit's lock reopened or half-erased the device (L-D1) | Medium | The quit task keeps the R15 mutex until exit; every dialog and `unlock` is `Cancelled` once quitting (spec 041 R17, T17) |
| L103 | A click timed by the page could accept a dialog unread (L-B1) | Medium | An accept within 1 000 ms is a decline; no dialog while the main window is unfocused (spec 041 R9, T09, Limits) |
| L104 | Chained dialogs, file dialogs included, could keep the user from quitting (L-B3) | Low | File dialogs share the slot; a 3 000 ms quiet period after any dialog; quitting cancels every dialog (spec 041 R9, R17) |
| L105 | Unlocks queued before the first open skipped the confirmation after a later lock (L-B2) | Low | The open count checked under the mutex (spec 041 R15, T16) |
| L106 | A panic inside a plan task's call left a dead device that never locked, and `flush` would write a half-done state (L-D3) | Low | The first poisoned hold starts the lock routine; a poisoned `Device` is dropped without `flush`, on the desktop and in 040's `close` (spec 041 R10, R17, T17; 040 R6) |
| L107 | Translated labels could carry access keys or lose placeholders (L-B4) | Low | Strings embedded at build time; a check of keys, placeholders, distinct labels and no `&` or `_` (spec 041 R9, T09) |
| L108 | The keychain entry could not be named once reset had deleted the data directory (L-A3, L-D5) | Low | The user is built from the canonical `app_local_data_dir()`, which always exists (spec 041 R16, T16) |
| L109 | The re-check after a yes had no stated result per kind (L-A1); T09 contradicted R15 on a yes to Unlock (L-A2) | Low | Each kind's target and result stated; T09 follows R15 (spec 041 R9, T09) |
| L110 | The kept slot could be overwritten by a concurrent import and outlived a decline (L-D4) | Low | The dialog slot claimed first; the kept slot emptied on every decline (spec 041 R6, T06) |
| L111 | Leftover web view directories deleted without the instance lock (L-A4); a non-regular file had three answers (L-A5); no accessor for the QR image (L-A6) | Low | Deleted only under `instance.lock`; `FileIo` via `symlink_metadata`; `Host::qr_image` (spec 041 R6, R8, Interface, Limits) |
| L112 | The macOS Esc behaviour could not be measured; the type is `rfd::MessageButtons`; §12, not §9, lists the UI languages (L-C4, L-A cosmetic) | Low | Manual check in the acceptance criterion; names and references fixed; AGENTS 11 amended at acceptance (spec 041 R3, R9; 040 Limits) |

Round 6. The confirmation rules added in rounds 3–5 had started to trap the honest user and did not hold on macOS; this round simplifies them (no question for the reviewer):

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L113 | The exit test and the host tests could not pass the input protection and the focus rule, and the host had no way to learn about focus (L-A1) | Blocker | `Dialogs` is async and reports focus; delays on the `tokio` clock; the exit test's dialogs answer after 1 000 ms (spec 041 R9, R18, Interface) |
| L114 | A parentless macOS confirmation is drawn by another process: it outlives the app and can keep the slot taken for good (measured, L-C1, L-B4, L-D4) | Medium | The confirmation is parented to the main window on macOS and Windows (a sheet, measured to keep the event loop running); Linux keeps a blocking dialog, and its hiding is a residual (spec 041 R9, Security, Acceptance criterion) |
| L115 | A too-fast accept counted as a decline and started 60 s of `Suppressed`; Return declines the default-safe Unlock and locked the user out (L-D1, L-B2) | Medium | A too-fast accept shows the dialog again with no penalty; `Unlock` is never suppressed; the quiet period is 1 000 ms (spec 041 R9, T09, Limits) |
| L116 | File dialogs skipped the focus rule and the input protection, so an Enter meant for the page could export a channel (L-B1) | Low | Every dialog follows the slot, focus and quiet rules; a too-fast save path is `Cancelled` (spec 041 R9, T09) |
| L117 | The lock routine started from a poisoned hold could wait on itself or lock a fresh unlock; R17 still flushed a poisoned `Device` (L-A2, L-B3) | Medium | Spawned as its own task, generation-tagged; no call on a poisoned `Device`, which is only dropped (spec 041 R10, R17, T17) |
| L118 | A server that repeats a panicking frame locked the device again at every unlock (L-D5) | Low | That plan is kept `failed` until one of its channels is left (spec 041 R7, R10, Interface, T17) |
| L119 | Two unlocks at start returned `Cancelled` to the second; after an erase the next unlock asked a confirmation inside the quiet period (L-A4, L-D2, L-D3) | Low | "Already unlocked" first under the mutex; a successful reset sets the open count to 0 (spec 041 R15, T16) |
| L120 | Reset deleted the live web view directory (L-A6) | Low | Left to the quit path and the next start (spec 041 R16) |
| L121 | The custom macOS menu dropped Edit, so paste stopped working; the `RunEvent::Exit` drop could block the main thread (L-B, note; L-B5) | Low | An Edit submenu kept; `try_lock` only (spec 041 R17) |
| L122 | `close` on a poisoned lock had no stated result (L-A5) | Low | `Internal`, no `flush`, poison cleared, then `Closed` (spec 040 R6, T06) |
| L123 | "1 000 ms after shown" is not measurable; Esc on each backend unverified (L-C2, L-C3) | Low | Measured from the host's `show` call; a manual Esc check on every backend (spec 041 R9, Acceptance criterion) |

Round 7, two passes (L-A, L-D), final:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| L124 | The `failed` plan was recorded by its `id`, which a new `Device` does not keep, so the L118 fix did nothing or failed another plan (L-A1, L-D1) | Medium | Recorded by its `channel_id`s (spec 041 R7, R10, T17) |
| L125 | The host had no way to refocus the main window (L-A2); the quick re-show failed the focus rule (L-D2) | Low | `Dialogs::focus_main_window`; the re-show skips the focus check (spec 041 R9, Interface, T09) |
| L126 | A panic in `on_tick` or a command belongs to no plan and locks at every unlock (L-D3) | Low | A documented residual (spec 041 R10, Security) |
| L127 | Whether rfd's GTK dialog can run off the main thread is read from source in round 5 and doubted from memory in round 7 (L-A3) | Low | Measured on Linux before PR slice (c) (spec 041 Acceptance criterion) |
| L128 | The unlock check order against quitting; "never suppressed" against the quiet period; the poison routine and the R15 mutex (L-A cosmetic) | Low | Stated (spec 041 R9, R10, R16) |

**Audit L stops here**, by diminishing returns: rounds 1–6 brought about 80, 50, 36, 25, 19 and 20 findings, round 7 five, and the last rounds only refined the desktop's native confirmations, which the implementation of spec 041 slice (c) will settle against the measurements the acceptance criterion names.

## Phase 4 drafts

**2026-09-26 — Decisions taken while drafting the phase 4 specs 040 and 041.** Not an audit: these questions came up while writing the bindings specs. The human reviewer decided Q1–Q3 with the recommended option before the specs were written. P1–P6 are drafting choices, recorded here for the review. The specs themselves stay `draft` until their own review.

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| Q1 | §10 asks Kotlin and Swift to "pass the same vectors as Rust", but most vectors test crate-internal functions that no platform call reaches, and the cryptography exists once, in Rust | Kotlin and Swift drive the real `Device` with every vector that reaches it (011 imports, 014 fingerprints, 028 `hello`). There is no second test-only library that re-exports internal functions. The exit criterion is reworded | Spec 040 R13, R14; specs 014 and 028 vectors amended; §10 |
| Q2 | `deny.toml` bans `rustls`, the macOS stack of `native-tls` has no TLS 1.3, which the server requires, and a WebSocket opened by the web view cannot use a SOCKS5 proxy | `clients/desktop/src-tauri/` is a workspace of its own with its own `deny.toml`, and uses `rustls` with `ring`, TLS 1.3 only and no resumption | ADR 0039; spec 041 R1–R3, R12; AGENTS 2 and §9 when 041 is accepted |
| Q3 | Whether spec 041 holds only the commands, or the whole Rust side of the Tauri process | The whole Rust side: commands, events, the socket host (TLS, SOCKS5, backoff, tick) and the keychain; spec 050 keeps the Svelte UI alone | Spec 041 |
| P1 | uniffi's `cli` feature, needed to generate the Kotlin and Swift sources, brings in `log` | The generator is a separate crate, `privatechat-uniffi-bindgen`, so that the shipped library links no logging crate (measured with uniffi 0.32.2) | Spec 040 R1 |
| P2 | ADR 0037 has the bindings make every `Device` call off the UI thread, and uniffi's generated methods are synchronous | A thin hand-written `Core` in Kotlin and Swift runs every call on one thread in call order and zeroes the byte arrays it was given. The apps may use only `Core`, which a script checks | Spec 040 R9, R10 |
| P3 | Who draws the 32 bytes of `K_db`: the desktop has no randomness source allowed outside libsodium | The core gains `generate_storage_key(out: &mut [u8; 32])`, used on all three platforms | Spec 040 R8; spec 027 Interface |
| P4 | JSON carries no 64-bit integer to TypeScript, and a server-supplied time can be any `u64` | Ids cross as hex strings, and `u64` values as `number` saturated at 2^53 − 1 | Spec 041 R5 |
| P5 | How the `.chatcfg` password and file cross the desktop IPC | The password as a raw IPC body, never JSON; the file read and written by the Rust side through the native dialog, so it never enters the web view | Spec 041 R6 |
| P6 | How phase 4 can open a channel against a real server with no test certificate trusted by the operating system | The exit test uses the onion path: a `ws://` onion URL through a test SOCKS5 proxy on loopback to the server's onion listener, which exercises the proxy code with no TLS hook in the product. TLS is tested separately against a local server with a `cfg(test)` root | Spec 041 R18, T12 |

## Audit K

**2026-09-25 — Audit K, review of the phase 3 draft specs 030–035 and ADR 0038 before human review, in four independent passes (K-A: coherence and SDD conformance; K-B: adversarial security and privacy; K-C: technical viability and simplicity; K-D: end-to-end scenarios), repeated in rounds until they bring nothing new.** Round 1:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K1 | A subscribe released just before a newer `hello` arrived was signed with the replaced nonce, got `bad_auth` and left the channel refused for the plan (K-A1, K-D1) | Medium | The previous nonce is kept; a signature under it gets `nonce_expired` and a `hello` repeating the latest nonce, not a failed attempt (spec 031 R1, R5, R9, T01) |
| K2 | The start-up line logged listener addresses, which the log test forbids (K-A2, K-C2, K-D5) | Medium | Ports and whether the onion listener is on, no address (spec 035 R4, T04, T05) |
| K3 | `PRIVATECHAT_DOMAIN` in `.env` would stop the server as an unknown `PRIVATECHAT_` variable (K-A3) | Medium | Renamed `SERVER_DOMAIN` (spec 034 R2, R3, R7) |
| K4 | The server was a binary only, so the exit test, the shutdown test and the log test could not run in process, and the tests of 031 and 032 needed spec 030's socket or spec 035's binary (K-A4, K-C1) | Blocker | `lib.rs` with `run(settings, clock, shutdown)` returning an `Outcome`; 027 R16 names the server's `pub` items; the log tests in their own process; 031's server tests over `AuthState`, 032's over the writer and reader; the SIGKILL test moved to 035 (specs 027 R16; 031 Interface, T01, T05–T09; 032 R3, T03, T10; 035 R7–R11) |
| K5 | `031.json` carried URLs and hosts as text, which spec 015 R1 forbids (K-A5) | Medium | Written as the hex of their ASCII bytes (spec 031 R10) |
| K6 | The two new fuzz targets amended only spec 016 R2, not its seed rule R8 and its nightly matrix R9 (K-A6) | Medium | Both amend R2, R8 and R9 (spec 030 R2, T02; 031 R11) |
| K7 | `Blocks` lines missing the phase 3 dependents (K-A7) | Low | Specs 010, 015, 016, 027, 028, 031, 032 brought up to date |
| K8 | §6 changes not listed: `HiddenServicePort 80`, HTTP 429 (K-A8) | Low | Listed under Public API changes (specs 033, 034) |
| K9 | The `server_id` retry loop and its numbers disagreed, and guarded against a 2⁻¹²⁸ event (K-A9, K-C10) | Low | A collision refuses that request with `server_full`, never retried (spec 032 R6, T06) |
| K10 | `relay::channel_id` and the other `relay` calls could fail with no stated effect (K-A10) | Low | `Error::Internal` from any `relay` call closes with 1011 (spec 030 R16, T16; 031 R5) |
| K11 | Backlog pages were bounded by rows only (500 × 64 673 B ≈ 32 MB), held until the socket took them, for 16 subscriptions per connection and thousands of connections: an out-of-memory attack from one IP, and a thundering herd after a restart (K-B1, K-D4) | Medium | Pages ≤ 500 rows and ≤ 1 MiB; 256 page permits for the whole server; one shared buffer per push (spec 030 R7, Tasks, Security, T07; 032 R9, T09) |
| K12 | `max_connections` shared by both listeners and no per-IP cap after authentication: a Tor flood or one IP could lock every user out with 503 (K-B2) | Medium | A per-IP cap on all open connections; each listener with its own caps, unauthenticated ones included (spec 033 R8, R10; 035 variables) |
| K13 | One IPv6 /64 could fill the 65 536-entry table and every new address was then refused (K-B3) | Medium | IPv6 keyed by /64; a full table admits new addresses under the listener caps (spec 033 R8, T08) |
| K14 | `ws://` onion URLs crossed any SOCKS5 proxy the user set, so a remote proxy put plain WebSocket on the LAN, readable and forgeable (K-B4) | Medium | A `ws://` channel is planned only behind a loopback proxy, otherwise `needs_proxy` (spec 027 R10, T10); ADR 0038 left unchanged, the rule narrows it |
| K15 | Old WAL frames could keep expired blobs on disk indefinitely (K-B5) | Medium | `journal_size_limit = 0`, a truncating checkpoint after each purge, and a test that no byte of a purged blob remains (spec 032 R2, R10, R13) |
| K16 | The reference proxies' error logs and Docker's unbounded log files kept client IPs on disk (K-B6) | Low | nginx `error_log stderr crit`; Caddy's two client-naming loggers discarded; the `local` driver with limits (spec 034 R2–R4) |
| K17 | A flooded channel overflowing its held pushes closed the whole connection, taking the other 15 channels down in a loop (K-B7) | Low | That subscription alone ends with `rate_limited`; spec 028 R16 re-queues it without stopping publishes (spec 030 R8, T08; 028 R16) |
| K18 | `ack` by `oneshot` and pushes through the hub were two paths, so an echo could precede its `ack` and acks could reorder (K-C4) | Medium | One path: the writer hands every result, with its connection and `client_ref`, to the hub in order (spec 030 R12, Tasks; 032 R7, Interface) |
| K19 | Deadlines under a `ManualClock` had nothing to wake them, and the 10 ms batch window was real time and made T05 flaky (K-C3) | Medium | Deadline owners wake every 100 ms of real time and compare `Clock`; the batch takes what is already waiting (spec 032 R5, R14) |
| K20 | No write deadline, and the pong deadline ignored a backlog queued ahead of the ping: a stuck peer held its buffers forever, and a slow link was closed in a loop and could stall a channel for good (K-C5, K-D3) | Medium | A write pending 30 s drops the TCP connection; the pong rule closes only when no write completed during the wait (spec 033 R4, R5, T04, T05) |
| K21 | The size quota counted free pages, so after a large expiry the server answered `server_full` for hours (K-C6) | Medium | Live pages only (spec 032 R8, T08) |
| K22 | "`SQLITE_IOERR` of a full disk" cannot be detected without `unsafe` and is already `SQLITE_FULL` (K-C7) | Low | Clause removed; T07 forces `SQLITE_FULL` with `max_page_count` (spec 032 R7) |
| K23 | The image: glibc of a trixie builder newer than the bookworm runtime, a `/data` the non-root user cannot write, SQLite temp files on a read-only root, `nginx -t` failing on the upstream name (K-C8) | Medium | Bookworm builder; `/data` and Tor's directory owned by their users; `temp_store = MEMORY`; `--add-host` (spec 034 R1, R5, R8, T01; 032 R2) |
| K24 | Tests whose sizes clash with the defaults (K-C9) | Low | Resized (spec 030 T07, T10; 033 T05) |
| K25 | Spec 100's lint, kept as 035 R7, guarded a state AGENTS already forbids (K-C10) | Low | Dropped (spec 035 Context) |
| K26 | `std::env::vars` panics on a non-UTF-8 variable (K-C11) | Low | `vars_os`; a non-UTF-8 `PRIVATECHAT_` name or value is a configuration error (spec 035 R1) |
| K27 | After `nonce_expired` the next subscribe left at once and met the 1 000 ms rule, and every `rate_limited` stopped all publishing for a minute (K-D2) | Low | Spacing counts across `hello`s; a `rate_limited` naming a channel and no `client_ref` re-queues that subscribe only (spec 028 R6, R16, T06, T16) |
| K28 | A restart whose start-up purge emptied the table reset `received_at` below the clients' cursors (K-D6) | Low | `last_received_at` kept in `meta`, read before the purge (spec 032 R1, R6, T06) |
| K29 | Tor users of a public server share an exit address under the per-IP limits (K-D7) | Low | Documented, with the values to raise (spec 033 Security; 034 R7) |

Round 2:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K30 | One address could fill the whole disk (256 connections × 30 publishes of 64 KB per 57 s ≈ 8.7 MB/s, 8 GiB in 16 min), and the onion listener faster (K-B1 round 2) | High | A byte budget per address (/64 and /48) and one for the whole onion listener; the residual stated: availability is outside the model (spec 033 R12, Security; 035 variables) |
| K31 | The 256 page permits could be held by a few slow or stalled connections, starving every subscription and tripping the client's 60 s silence rule (K-B2, K-D1 round 2) | High | One permit per connection, 64 for the onion listener, a page written within 30 s or close 1013, and a permit wait over 20 s ends the subscription with an error (spec 030 R7, Limits, Security, T07) |
| K32 | Subscribing to one's own channel made a connection "authenticated", so 16 IPv4 addresses or one /56 could hold every main-listener slot (K-B3 round 2) | High | `ip_connections` lowered to 64; IPv6 also counted by /48 at four times the /64 limits (spec 033 R8, Limits, T08) |
| K33 | IPv4-mapped IPv6 put every IPv4 client in one `::/64` bucket and broke trusted-proxy matching (K-B4 round 2) | Medium | `IpAddr::to_canonical` before keying and matching (spec 033 R8, T08) |
| K34 | `expires_at` from `received_at` kept blobs past their TTL after a clock excursion or a flood that runs `received_at` ahead (K-B5 round 2) | Medium | `expires_at = wall + ttl` (spec 032 R6, T06) |
| K35 | The previous-nonce rule could be repeated at will for 16 verifications a second with no failure charged (K-B6 round 2) | Low | It applies only within 10 s of the latest `hello`; the cost stated as 16 (spec 031 R5, Limits, Security, T01) |
| K36 | A truncated WAL gives its disk blocks back unwiped; R13 only proves what the files hold (K-B7 round 2) | Low | Stated in spec 032 Security, with disk encryption at rest as the defence |
| K37 | Spec 028 R4 still said the server closes the connection when the held-push bound is reached (K-A1, K-C5, K-B note, round 2) | Medium | 028 R4 amended to the ending of one subscription |
| K38 | `main.rs` could not build `SystemClock` or tell `StartError` from `ConfigError`, and the exit test could not learn the server's port (K-A2, K-A3, K-C1 round 2) | Medium | `bind` → `Bound::local_addrs` → `Bound::run`; `SystemClock`, `StartError` with its reason and `ConfigError` `pub`; the test's URL has no port and the harness connects to the bound address (spec 035 R10, R11, T10; 027 R16; 032 Interface) |
| K39 | Two types named `Outcome` (K-A4 round 2) | Low | The writer's is `WriteOutcome` (spec 032) |
| K40 | `run` cannot be coerced to a function pointer (K-A5, K-C round 2) | Low | A compile-only call pins it (spec 035 T10) |
| K41 | 031 T06 relied on a socket test that 030 did not have (K-A6 round 2) | Low | 030 T06 covers the third failure and the first-subscribe deadline on a socket |
| K42 | A full writer queue had no stated answer to the publisher (K-A7 round 2) | Low | `rate_limited` naming both fields, at once (spec 030 R11, T11) |
| K43 | T04 had no file, and no one installed the stderr subscriber (K-A8, K-C2 round 2) | Medium | `main.rs` calls `log::init`; `run` never does; T04 in `s035_log.rs`; R5 and R6 checked inside the exit run's process; the configuration message is the one direct stderr write (spec 035 R4, R5, Interface, T04, T05) |
| K44 | A subscription ended under 030 R8 could still send its `ok` or pushes after the error, leaving the client subscribed to nothing (K-D2, K-C6 round 2) | Medium | Ending is decided under the hub's lock and stops everything of it; the client answers `Reconnect` to a `rate_limited` naming a subscribed channel (spec 030 R8, T08; 028 R16) |
| K45 | `probe_plan` ignored the loopback-proxy rule, and `localhost` trusted a resolver (K-D3, K-B note round 2) | Low | `probe_plan` refuses `ws://` behind a proxy that is not a loopback IP literal; `needs_proxy` worded as "a proxy on this device" (spec 027 R10, R12, T10) |
| K46 | Deadlines ran on the wall clock, so a clock step fired every ping at once or none for an hour (K-D4 round 2) | Low | `Clock::mono_ms` for every deadline and window; `wall_ms` only for `received_at`, `expires_at` and the purge's `now` (spec 032 R14, T14; 033 Interface) |
| K47 | The exit harness never reopened a socket closed by the server, and could outrun the server's 100 ms wake (K-D5 round 2) | Low | It reopens every closed socket still in the plan and paces the clock after the frames and 100 ms of real time (spec 035 R11) |
| K48 | A link under about 17 kbit/s cannot take a 64 KB frame within the write deadline (K-D6 round 2) | Low | The floor is stated (spec 033 Security); the write deadline counts from the start of one write (spec 033 R5) |
| K49 | Carrier-grade NAT and offices meet the per-IP limits (K-D7 round 2) | Low | Documented with `ip_connections` among the values to raise (spec 033 Security; 034 R7) |
| K50 | A stalled client made every graceful stop `Fatal` (K-C3 round 2) | Medium | Closes are queued, 2 s wait, then TCP dropped, which is not a failure (spec 035 R7, T07) |
| K51 | Compose's 10 s grace period raced the server's 10 s shutdown (K-C4 round 2) | Medium | `stop_grace_period: 15s` (spec 034 R2, T02) |
| K52 | nginx logs unknown SSL errors with the client's address at `crit` (K-C7 round 2) | Low | `error_log /dev/null emerg` (spec 034 R4) |
| K53 | A real-time bound in 032 T14 would be flaky; T08 had no way to send SIGTERM without `unsafe` (K-C8 round 2) | Low | Polling up to 5 s; `kill -TERM` through `Command` (spec 032 T14; 035 T08) |
| K54 | Simplifications: a separate log-test run, `Arc<[u8]>` against axum's `Bytes`, a 100 ms wake in every connection task (K-C S1–S3 round 2) | Low | The log checks inside the exit run; `Bytes`; one server-wide deadline task (specs 035, 030, 032 R14) |
| K55 | Test hooks had no stated gate (K-B note round 2) | Low | `cfg(test)`, and `ManualClock` only under `test-support`; a release build checked without it (spec 035 R10, T10; 030 T16) |

Round 3:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K56 | The server-wide pool of page permits could still be held by one /48 or four IPv4 addresses, a connection's own subscriptions used up each other's 20 s wait, and a 1 MiB page in 30 s set a catch-up floor of about 280 kbit/s (K-B1, K-D1, K-D2, K-D3, K-C4, K-C5 round 3) | High | The pool, the 20 s wait and the page deadline removed: pages of ≤ 256 KiB, one in memory per connection, streamed in turn; each connection pays for its own page, and the per-frame write deadline of 033 R5 remains the only floor (about 17 kbit/s) (spec 030 R7, Limits, Security, T07; 032 R9, T09) |
| K57 | A channel flooding at its limit could overflow its hold after `ok` on a slow link, and the client could only reconnect, dropping the other 15 (K-D4 round 3) | Low | Held pushes are sent before `ok`, and `ok` is sent when none is left, under the hub's lock: a subscription can end only before `ok`, which the client re-queues (spec 030 R7, R8, T08; 028 R4, R16, T04) |
| K58 | `bind` opened the database without the clock the writer needs (K-A1, K-C1 round 3) | Medium | `bind(settings, clock)`, `Bound::run(shutdown)` (spec 035 R10, R11, Interface) |
| K59 | 030 tests exceeded spec 033's fixed per-connection limits once 033 lands (K-A2 round 3) | Medium | Sized to 30 publishes per connection and run with the channel limits raised; the queue filled by a hook (spec 030 T08, T11, T12) |
| K60 | The backlog read's `now` is a wall-clock comparison that R14 did not allow (K-A3 round 3) | Medium | Named in 032 R14 and 030 R7 |
| K61 | The harness moved one clock reading, took 2.4 h of real time for the final move, and could reopen before the restarted server was bound (K-A4, K-C2, K-D scenario 6 round 3) | Low | Both readings move together, the final move in one step with the purge polled, and sockets reopen after the new `bind` (spec 035 R11) |
| K62 | Small ones: `Instant::now` unchecked, `StartReason` unlisted, the previous-nonce rule missing from the §6 list (K-A5, K-A6, K-A §6 round 3) | Low | Specs 032 T14; 027 R16, 035 R10 and Interface; 031 Public API changes |
| K63 | `cargo tree -e features` shows dev-dependency features; T04's warn filter and `log` check had no mechanism; T05's IP scan hit module paths; the WAL file is deleted, not emptied; the sync `bind` and T08's reserved port (K-C3, K-C6–K-C9 round 3) | Low | `-e normal,build,features`; T04 filters its capture and checks `log::max_level`; `with_target(false)` and a defined tokenizer; "empty or absent"; std listeners made non-blocking; port 0 read from the start line (spec 035) |
| K64 | The /48 multiplier on bytes and new connections let one device lock out a carrier's /48, and the shared byte budget was missing from the NAT note (K-B2, K-D scenario 3 round 3) | Low | The /48 count only for open connections; `ip_bytes_per_min` in the note and the guide (spec 033 R8, R12, Security; 034 R7) |
| K65 | A server clock step deletes or keeps blobs by the size of the step and upsets short-TTL channels; R6 claimed too much (K-B3, K-D5 round 3) | Low | Stated as a residual in 032 Security, with slewed authenticated time sync in the guide (spec 032 R6, Security; 034 R7) |
| K66 | A repeated `hello` could restart the 10 s previous-nonce window (K-B4 round 3) | Low | The window counts from the first `hello` of the latest nonce (spec 031 R5, Limits, T01) |

Round 4:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K67 | Holds were bounded per subscription, so one connection could pin 16 × 4 MiB for as long as a trickled catch-up lasts: about 4 GiB from one IPv4 address and 68 GiB through the onion listener (K-B1 round 4) | Medium | One hold bound of 256 frames and 4 MiB for all of a connection's subscriptions, ending the one holding most; about 8.3 MiB per connection in all, stated with the memory to plan for (spec 030 R8, Limits, Security; 034 R7) |
| K68 | After K64 a /48 had no byte bound: rotating /64s filled 8 GiB in about 15 minutes (K-B2 round 4) | Medium | A /48 byte budget at sixteen times the /64's (spec 033 R12, Limits) |
| K69 | A re-queued subscribe was always past the client's 50 s nonce window, so every ended subscription became a full `Reconnect` (K-D1 round 4) | Medium | A re-queued subscribe is released however old its nonce; the server's `nonce_expired` and fresh `hello` re-queue it under the new one (spec 028 R7, T16) |
| K70 | The connection task could write backlog pages ahead of its queue, delaying `ack`s and live pushes of subscribed channels into a 1013 close; `ok` was not counted (K-D2, K-C4 round 4) | Low | The queue is written before each backlog page and held batch; `ok` counts (spec 030 R7, R10, T07) |
| K71 | A short-TTL channel waiting its turn could lose its backlog to expiry with no banner, and `synced` then hid it (K-D3 round 4) | Low | Truncation checked again at `ok`; no `synced` there when found (spec 028 R9, T08) |
| K72 | tungstenite never sends 1009 by itself; recognising `Capacity` behind `axum::Error` needs `tungstenite` as a direct dependency (K-C1 round 4) | Medium | Added, default features off, at the version axum pins (spec 030 Interface) |
| K73 | Tests that depended on kernel buffer sizes and on stored rows beyond the channel limits (K-C2, K-C3, K-A3, K-A4 round 4) | Low | A 65 536-byte receive buffer, a `cfg(test)` read counter stable over 500 ms, rows through `submit` with limits raised, the 4 MiB and 256-frame bounds each reached (spec 030 T07, T08, T10; 033 T05) |
| K74 | The writer had no stop operation for the shutdown's drain and checkpoint (K-C5 round 4) | Low | `Writer::finish`, awaited under the 10 s limit (spec 032 Interface; 035 R7) |
| K75 | The rust skill contradicted the specs on the writer and on network timeouts (K-C6 round 4) | Low | Both bullets point to specs 032 and 033 |
| K76 | Small ones: the causes of a database refusal, a wrong reference, T11's pacing claim, R5 worded as a presence (K-A1, K-A2, K-A5, K-A7 round 4) | Low | `DbCause`; specs 032 R3, R14, T03; 033 T11; 035 R5; 027 R16 |
| K77 | ADR 0038 said a config moved to the other scheme would become another channel's; `channel_id` does not depend on `server_url` (K-A6 round 4) | Low | The consequence corrected in the ADR (accepted today, in this branch, not yet reviewed): only the route's `tls` changes. Logged here as the correction the ADR README allows |
| K78 | An intruder flooding a channel at its limit can keep a member on a link slower than about twice the flood from finishing that channel's catch-up (K-B3 round 4) | Low | Stated as a residual of a flooded channel, whose answer is a new channel (spec 030 Security) |

Round 5:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K79 | The truncation re-check at `ok` used the cursor, which any surviving backlog push had already moved past the expired stretch, so messages could be lost with no banner (K-D1 round 5) | Medium | The re-check uses the `last` captured when the subscribe was first queued (spec 028 R9, T08) |
| K80 | One /48 could fill the shared IP table with its own /64s and then escape every per-address bound, taking the connection caps and filling the disk (K-B1 round 5) | High | IPv6 entries per /48 with at most 256 /64s inside, never a /64 without its /48; a full table still checks every known address (spec 033 R8, Limits, Interface, T08) |
| K81 | The ping's own write always completes, so R4 never fired for a peer that had stopped reading (K-A1 round 5) | Medium | The ping's own write does not count as progress (spec 033 R4) |
| K82 | The builder image has no `make`, which the vendored libsodium build needs: the image could not build (K-C1 round 5) | Blocker | `make` installed in the builder stage (spec 034 R1) |
| K83 | On Linux the kernel absorbs megabytes before a non-reading client stalls the server, so the queue, hold and shutdown tests could not reach their bounds (K-C2 round 5) | Medium | A `cfg(test)` hook that pauses a connection's socket writes (spec 030 Interface, T08; 033 T05; 035 T07) |
| K84 | Small ones: 030 T06's single clock step also tripped the ping rule; 035 R4's closed event list forbade the `debug` events its tests need; 035 R7's order did not fit `Writer::finish`; 028 R4 still said the bound was per subscription; 032 R7 covered only a failing commit (K-A2–K-A5, K-C3 round 5) | Low | Specs 030 T06; 035 R4, R7; 028 R4; 032 R7 |

Round 6:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K85 | The /48 bounds were fixed multiples, so a few devices in a mobile carrier's shared /48, or more than 256 honest connections from it, kept the rest out and the operator could not fix it (K-B1, K-D1 round 6) | Medium | Four configurable `ip48_` values in place of the multipliers; the shared carrier /48 stated with them among the values to raise (spec 033 R8, R12, Limits, Security, T08; 035 variables; 034 R7) |
| K86 | A primary-key failure on `server_id` would now roll back the whole batch, and a rollback left the in-memory counters, windows and `last` inflated (K-A1 round 6) | Medium | A `SELECT` finds a used id and refuses that request alone; counters, windows and `last` change only on commit (spec 032 R6, R7, T07) |
| K87 | What a failed backlog read does was unstated, and the shutdown closed the database under running streams (K-A2 round 6) | Medium | A failed `read_page` closes with 1011; backlog streams stop at shutdown step 1; `StoreError` defined (spec 030 R7, T16; 032 Interface; 035 R7) |
| K88 | A short-TTL channel queued last could lose history waiting for its subscribe turn (K-D2 round 6) | Low | Subscribes released in ascending `last + ttl_ms` (spec 028 R6, T06) |
| K89 | Measured deploy details: Tor refuses a host name as `HiddenServicePort` target; Caddy's catch-all TLS policy and a required `SERVER_DOMAIN` for `caddy validate`; `.env` absent in CI; an override cannot remove a service; T08's binary needs URLs and a database path (K-C85–K-C89 round 6) | Low | Specs 034 R5, R8, T02, T03; 035 R4, T08 |
| K90 | Caddy has a JSON switch for session tickets but no Caddyfile form (K-C90 round 6) | Low | Recorded in the open question 034-R3, with the recommendation to keep the Caddyfile |

Round 7:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| K91 | "Change only on commit" made the blobs of one transaction see the values from before it: equal `received_at`s and limits crossed by up to 255 blobs (K-A round 7) | Medium | A working copy per transaction, committed or discarded; the channel checks count the transaction's own blobs (spec 032 R7, T06; 033 R6, R7, T07) |
| K92 | Docker's IPv4 userland proxy gives every IPv6 client one address at Caddy, so one IPv6 client could lock every IPv6 user out through the per-IP limits (K-B1 round 7) | Medium | IPv6 enabled on `front` with a fixed ULA subnet; the guide requires hosts that keep the real address (not rootless Docker, not ip6tables disabled) (spec 034 R2, R7, T02) |
| K93 | One Tor client can use up the shared onion byte budget for every onion user (K-B2 round 7) | Low | Stated as a residual of an address-free listener, with the values to raise (spec 033 Security; 034 R7) |
| K94 | With seconds of download delay, two re-queued subscribes signed with the old nonce could straddle the 10 s window and one would get `bad_auth` and stay refused (K-D1 round 7) | Medium | At most one stale-nonce subscribe outstanding; the fresh `hello` re-queues the rest (spec 028 R7, T16) |
| K95 | The test client, the exit harness and the smoke example need `futures-util` for `SinkExt`/`StreamExt`, and T04 needs `log` (K-C1 round 7) | Low | Added to the dev-dependencies; the axum/tungstenite pin explained (tungstenite 0.30 brings the banned `chacha20`) (specs 030, 034, 035) |

## Phase 3 drafts

**2026-09-25 — Decisions taken while drafting the phase 3 specs 030–035.** Not an audit: writing the server specs raised these questions. The human reviewer decided P2–P4 with the recommended option before the specs were written. P1 had no alternative and P5–P7 are drafting choices, all recorded here for the review. The specs themselves stay `draft` until their own review.

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P1 | The WebSocket stack fixed by §9 (`axum` + `tungstenite`) brings `sha1` and `rand`, which `deny.toml` bans. Every WebSocket server needs SHA-1 for the RFC 6455 handshake, and `tungstenite` uses `rand` only for client masks | Named wrapper exceptions: `sha1` under `axum` and `tungstenite`, `tungstenite` added to the wrappers of `rand` (AGENTS 2 allows a justified wrapper exception) | Spec 030 R1, T01 |
| P2 | `server_url` must be `wss://`, and a TLS certificate for a `.onion` name is out of reach for most operators, so the onion service of §1, §2 and §6 would exist only on paper | `ws://` allowed for v3 onion hosts only, opened with no TLS and only through Tor | ADR 0038; spec 011 R5, R6, T05, vectors; spec 027 R10, `Route::tls`; §5, §6 "Transport", §12 |
| P3 | Spec 100-log-test was parked until the first crate that logs, and its open question left the choice to spec 035 | Spec 035 takes over its R1–R3 as R5–R7, and the file is deleted | Spec 035; AGENTS 19; §8, §10; specs 010, 013, 021 (references); `specs/README.md` |
| P4 | How the server reads its configuration | Environment variables only, no file and no parser dependency; an unknown `PRIVATECHAT_` variable stops the server | Spec 035 R1 |
| P5 | §6 exempts connections from `127.0.0.1` from the per-IP limits "for the .onion service", but behind a reverse proxy on the same host every client comes from a local address | A second listener for the onion service, carrying no client address; the per-IP limits apply on the main listener only | Specs 033 R8, R9; 035 R2; 034 R2, R6 |
| P6 | §6 calls every limit configurable, but the client paces itself against the per-connection ones (spec 028 R6, R15) | Per-connection limits are protocol constants; the channel, IP and global limits are configurable. The server's publish window is 57 000 ms, so network jitter cannot refuse a client that keeps to 30 per 60 000 ms | Spec 033 R1, R11 |
| P7 | §6 "Order and time" computes `received_at` per process, and a restart with a clock set back would give new blobs times below the clients' cursors | The writer starts from the largest stored `received_at` | Spec 032 R6 |
| P8 | Caddy turns off TLS session tickets only in JSON, not in the Caddyfile, while §6 asks for no tickets (open question 034-R3) | Decided with the human reviewer after audit K: keep the Caddyfile with tickets on and document them as unused, since the clients never resume a session; nginx keeps them off | Spec 034 Open questions, Security, R7 |

## Audit J

**2026-09-25 — Audit J, review of the phase 2 draft specs 020–028 before human review, in four independent passes (J-A: coherence and SDD conformance; J-B: adversarial cryptography and protocol; J-C: technical viability and simplicity; J-D: end-to-end scenarios), repeated in rounds until clean.** Round 1: 105 findings (J-A1–J-A35, J-B1–J-B15, J-C1–J-C27, J-D1–J-D28), five Blockers, no break of the key hierarchy, of encrypt-then-sign or of the verification order. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J1 | A stored channel could not be reopened (no call gave back its `Config`), an open channel exposed neither its identity nor its invitation, and the four handles of §9 cannot cross uniffi (by-value moves, borrowed returns, `Box<dyn Store>`, nothing `Send`) (J-C1, J-C4, J-C5, J-D1, J-D2, J-D20, J-A1) | Blocker | One `Device` handle called by id (ADR 0037, `proposed`); `Channel::create`/`open_stored`/`config`; `Store` and `Vault` `Send` (specs 020, 021, 027, 028) |
| J2 | `commit` took a non-`Clone` batch by value, so nothing was left to install in memory or to retry (J-C2) | Blocker | `commit(&WriteBatch)`, `compact(state, now)`; the store keeps no copy of the state (spec 020) |
| J3 | Crash points under `cfg(test)` were unreachable from an integration test, and fired only once (J-C3, J-A3) | Blocker | The exit test lives in `crates/store/src/tests/`; crash points take a count, and a fault injector fails the *k*-th system call (specs 020, 028) |
| J4 | An intruder could plant 530 permanent retired records (a text, then a `key_retired`), closing the channel to new keys and blocking regeneration for ever (J-B1) | High | A retirement from a stranger removes the stranger; only labelled or verified peers become retired by a message; `forget` removes retired records; one's own old keys live in their own list of eight and regeneration is never refused for room (specs 024, 025, 026; §4, §7) |
| J5 | A full log lost messages silently (the cursor moved past a failed commit), could suppress the own-key alert for good, and blocked the pending `key_retired` (J-B2, J-A4, J-D14) | High | A log headroom checked before any verdict, with a reserve for acks and own-key records; a store failure stalls the channel for the connection and leaves the cursor (specs 021, 028) |
| J6 | Lowercasing before the UTS #39 skeleton let "AIice" and "B0b" pass; invisible characters outside Cf passed; the Cf table was to be generated against 015 R4 and ADR 0036 (J-B3, J-C8, J-A10, J-A11) | High | Skeleton, lowercase, skeleton; one hand-written table of Cf and `Default_Ignorable_Code_Point`; no vector file for a local comparison (spec 022; ADR 0036 amended before its first commit) |
| J7 | Streaming pages without an end marker let a live push move the cursor past an unsent backlog; the server could hide deletions through `oldest_retained_at`; a future `received_at` poisoned the cursor for good; every junk push rewrote `state.bin` (J-B4–J-B7, J-D13) | Medium | The server sends the backlog before `ok` and no live push before it; truncation judged by the client clock; the cursor clamped to `now`; cursor-only commits at most once a minute (specs 021, 028) |
| J8 | Session gaps: 16 subscribes in one millisecond against "1 authentication attempt/s", a late channel waiting for a `hello` that never comes, re-subscribing and republishing on a second `hello`, rejected publishes stuck in flight, error codes without their channel, `ack` outcomes invisible (J-D5–J-D7, J-D11, J-D12, J-D28, J-B8, J-B14, J-A14) | High | One `subscribe` per second, `Reconnect` past the nonce window, only unsubscribed channels re-subscribed, in-flight and queued sets, every error code with its effect, `AckOutcome`, `abandon` (specs 021, 028) |
| J9 | Own messages: hidden before they could be sent in a short-TTL channel, placed before the message they answer, unmatchable to their `ClientRef`, and a thief's messages indistinguishable from one's own (J-D8–J-D10, J-D15, J-B15) | High | Listed while publishable, ordered by real times, `client_ref` in `Message`, `Sender::OwnKeyElsewhere` (specs 021, 023) |
| J10 | Storage: sizes checked after reading, a late `fsync` failure breaking R10, two stores on one directory, log entries not bound to their channel, a deleted settings file silently dropping Tor (J-C9, J-C10, J-C12, J-B11, J-B12, J-A5, J-A8, J-A9) | High | Sizes before reading; poisoning after a late failure; one live store per directory; per-directory and settings keys; `settings_reset` (spec 020; ADR 0035 amended before its first commit) |
| J11 | Kept signatures of a retired key could not be told apart after a reopen (J-A7) | Medium | An `epoch` in each kept signature; §4 reworded (spec 021) |
| J12 | Phase 2 fuzz targets not added to spec 016, `MemoryStore` invisible under `cfg(fuzzing)`, a random identity in a fuzz target, dependencies against the merged `s010_t25` (J-A2, J-C6, J-C7) | High | Each spec amends 016 R2, R8, R9; `testing` under `cfg(any(test, fuzzing, feature = "test-support"))`; `Channel::for_fuzzing`; 020 and 022 amend 010 R16/T25 |
| J13 | PR slices over 400 lines; duplicated rules; tests of later specs inside earlier ones; missing `FailingStore` tests; `commits = 0` missing; an unworkable `api_surface.txt`; a no-oracle property false as stated (J-C11, J-C15–J-C19, J-A15, J-A19, J-A20, J-A30, J-B13) | Medium | Slices in every spec; one owner per rule; hooks until the later spec lands; a `FailingStore` test per stateful spec; `unreachable_pub` and function-pointer coercions; R16 scoped with its two documented exceptions |
| J14 | Small ones: the `proto_versions` cap, header `Blocks` lists, the vectors text fields, the late `ack` of a retirement, `DEFAULT_SERVER_URL`'s owner, the new domain tags in §4, a T22 boundary, a log minimum size, the pre-verification label rule, the own-name claim, a direction of re-sealing, the Unicode test file (J-A12, J-A13, J-A16–J-A18, J-A21–J-A35, J-B9, J-B10, J-C13, J-C14, J-C20–J-C27, J-D16–J-D19, J-D21–J-D27) | Low | Corrected in the specs, `specs/vectors/README.md`, spec 015 R1, spec 016 R2 and §4, §7 |

Round 2: 85 findings (J2-A1–J2-A24, J2-B1–J2-B10, J2-C1–J2-C21, J2-D1–J2-D28), no Blocker, 9 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J15 | With ticks every 10 s only five subscribes fit the 50 s nonce window, so connections with more channels reconnected for ever (J2-A1, J2-D1) | High | `on_tick` at least every 1 000 ms; subscribes 1 100 ms apart (specs 027 R12, 028 R6, R7) |
| J16 | A repeated `ok` reset the gap baseline at will, and truncation was decided after the backlog it concerned (J2-B1, J2-B2, J2-D5, J2-D6) | High | Truncation decided when the subscribe is queued; an `ok` accepted once; `synced` moves the cursor at `ok`, so a quiet channel is not flagged (specs 021 R19, 028 R8, R9) |
| J17 | A proxy switched on kept direct sockets whose channel set did not change; the SOCKS username revealed the `channel_id` prefix to observers of a remote proxy; a lost settings file connected before the warning (J2-D2, J2-D3, J2-D9, J2-B4, J2-B7) | High | The route is part of a plan's identity; the username comes from the keyed directory name; nothing connects while the settings are reset, and corrupt settings count as lost (spec 027 R1, R2, R10) |
| J18 | A not-delivered own message was never on screen, stale in-flight entries never timed out, and the tick path reported nothing (J2-D4, J2-B3, J2-A4) | High | Own messages listed until their `purge_at`, shown `NotDelivered` once they cannot leave in time; in-flight entries time out a minute later; every `outbox` path reports (specs 021 R21, 023 R1, R3, 028 R14) |
| J19 | The on-disk exit test needed about 90 000 fsyncs, each state seal wiped 2.25 MiB, and the fault injector raced across parallel tests (J2-C1–J2-C3) | High | A counted no-op `fsync` mode under `cfg(test)`; buffers at the exact encoded length; faults per instance; crash points through a child process with `Command::env` (spec 020) |
| J20 | A full log still hid the own-key alert and stalled the retirement; a stale-message own-key event contradicted "no event"; queued entries a thief had overtaken still showed `Delivered` (J2-B5, J2-B9, J2-D7, J2-A5) | Medium | Under `LogFull` the own-key event is committed alone; a `LogFull` stall stops receiving only and ends when room returns; overtaken entries are removed as not delivered (specs 021 R14, R18, 028 R10, R13) |
| J21 | A lost `ack` duplicated blobs on reconnect; `send` dropped the events of its `outbox` step; `Delivered` did not say where the row goes; no `on_disconnect` in `Session` (J2-D12, J2-D16, J2-D19, J2-D18, J2-A2, J2-A3) | Medium | An echo matching an `outbox` entry acknowledges it; `send` and `regenerate_identity` return their events; `Delivered` carries `server_id` and `received_at`; `Session::on_disconnect` |
| J22 | Store failures: no reopen of a poisoned store, a compaction failure before its state write poisoned anyway, broken channels without a reason, a failed `leave` hid the channel (J2-D8, J2-D10, J2-D26, J2-D27, J2-C10) | Medium | Poison only at or after the state rename; `Device` reopens or moves to `broken` with the reason; `replace_broken` on import; a failed `leave` keeps the channel (specs 020 R11, 027 R5, R8, R14, R15) |
| J23 | Plans reshuffled every run on each create or leave; the probe socket's route was undefined (J2-D13, J2-D14, J2-D21) | Medium | Stable runs; `probe_plan` with a fresh SOCKS username; `probe_hello` applies 028 R2 (spec 027 R10, R12) |
| J24 | The periodic purge rewrote the whole log every minute; `own_old_keys` dropped young keys; a `key_retired` un-muted a spammer; an old-key entry could follow its retirement (J2-B6, J2-B8, J2-B10, J2-D11) | Medium | Purge when expired records reach 1 MiB, a quarter of the log or a day; sixteen old keys, expired ones dropped first; a muted unknown keeps its record with a closed counter; the retirement waits for the old key's entries (specs 023 R5, 024 R2, 025 R1, R4) |
| J25 | Boundary: `Config` still `pub` in 011, the 016 reach check blind to `pub(crate)` and `decode`, `unreachable_pub` cannot prove "exactly", `dead_code` allows removed too early, `FailingStore` could not fail a compaction and no `FailingVault` existed, `state_eq` failed on the store's own fields (J2-A7–J2-A9, J2-A18, J2-A20, J2-C4–J2-C8, J2-C15, J2-C19–J2-C21) | Medium | 027 amends 011 and 016 R6, removes the allows; api-surface tests in both crates and review for extras; `FailingStore` counts `compact`, `FailingVault`, `state_eq` ignores log positions; `Event` defined in 028 |
| J26 | AGENTS 22 (`ct_eq` for every `[u8; N]`) against lookups and orderings by public identifiers (J2-C9) | Medium | Open question 021-R9 with a recommendation for the human reviewer |
| J27 | Small ones: §7 name-key order and "Unknown ⇔ label IS NULL", stale §4 wording, the size figures, the entry length prefix in the headroom, the 45-byte minimum, `purge_at` of a foreign own-key record, header pairs, 014 and 017 obligations, `expires_at` for rows, `fingerprint` of any key, `ExportedFile`, `set_local_name`, `duplicate`, PR slice order, the session fuzz input, directory `fsync` errors, and more (J2-A10–J2-A17, J2-A19, J2-A21–J2-A24, J2-C11–J2-C14, J2-C16–J2-C18, J2-D15, J2-D17, J2-D20, J2-D22–J2-D25, J2-D28) | Low | Corrected in the specs, §4 and §7 |

Round 3: 75 findings (J3-A1–J3-A21, J3-B1–J3-B10, J3-C1–J3-C19, J3-D1–J3-D27), no Blocker, 5 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J28 | After a `LogFull` stall or a store failure, the `ok`'s `synced` or a later push moved the cursor past the dropped blobs, which were never sent again (J3-B1, J3-D1) | High | A dropped push freezes the channel for the connection: no later `decrypt`, no `synced`, and a reconnect from the same cursor once room returns or after the reopen (spec 028 R9, R10) |
| J29 | `synced` put the local clock into the server-time cursor, so a fast clock skipped messages; `synced` never committed, so quiet channels were flagged after every unlock (J3-B4, J3-D2, J3-D3) | Medium | `synced_at` kept apart from the cursor, local time, committed by the once-a-minute rule and used only for truncation (spec 020 key 17, spec 021 R20, spec 028 R8) |
| J30 | A stall hid the own-key alert from every push after the first, and the `LogFull` own-key commit ignored the retention rule, so an old replay raised a false alarm (J3-B2, J3-B3, J3-D4) | Medium | `check_own_key` runs `verify` and `open` with no state and applies the `2·(ttl_ms + 360 000)` rule; the session runs it on every push of a stalled channel (spec 021 R19, spec 028 R10) |
| J31 | A failing `leave` could not keep a channel it had consumed; the `Device` could not tell which channel failed inside a session step; `OutboxFull` reopened a healthy store (J3-C1, J3-C2, J3-A4, J3-A5, J3-D5, J3-D6, J3-C4) | High | `destroy` and `leave` take `&mut self`, a failure after the rename is `Ok`; `Session` returns a `Step` with per-channel failures; only `Io` and `Corrupt` reopen (specs 020 R21, 021 R27, 027 R8, R14, 028 Interface) |
| J32 | The `store` tests could not build a batch; the exit test could not reach the state it compares and sat in a spec its `Device` depends on (J3-C3, J3-C6, J3-A7) | High | `testing` builders and `FailingVault::last_committed`; the exit test moved to spec 027 (R23) |
| J33 | A message dated to expire on arrival was consumed, moved `max_counter` and was never shown, hiding a deletion (J3-B5) | Medium | `decrypt` rejects it as `Expired` after `verify`; open question 021-R9 proposes adding the clause to §4 |
| J34 | A full log was rewritten for every push once one record expired; the periodic purge's 1 MiB clause amplified writes (J3-B6, J3-C8) | Medium | The headroom compacts only when a mebibyte has expired; the periodic purge only at a quarter of the log or a day (specs 021 R18, 023 R5) |
| J35 | Refused, unsubscribed or unsupported channels never cleaned their `outbox`; a pending retirement was re-sealed every minute offline; entries removed by the own-key rule gave no event; broken channels stayed in the plan (J3-D7, J3-D8, J3-D13, J3-D19, J3-B9) | Medium | `expire_outbox` for every channel not subscribed, with no re-seal; removed entries queued as outcomes; a broken channel leaves its run (specs 021 R14, R23, 027 R12, R14) |
| J36 | The probe ignored the settings gate; a fresh install showed "settings lost"; imports over a broken channel lost its reason and could delete a newer app's data; refused channels blocked good ones; the SOCKS username linked a device's channel across plans (J3-B7, J3-B8, J3-D9–J3-D12, J3-A6) | Medium | `probe_plan` gated; the flag only when channels exist or the file is bad; the broken reason returned and `replace_broken` for `Corrupt` only; refused channels skipped until the plan changes; a random username per plan (spec 027 R1, R2, R5, R10, R11) |
| J37 | Small ones: `OutboxStep` for clippy, `MessageContent`, `OwnKeyElsewhere { pk }`, `Delivered.expires_at`, `decrypt` returning an `Option`, the 1 000-message channel property, the pacing figure, the pause on `after_send`, the hold of a refused retirement, the wait for a `hello`, R19's keep-if-logged rule, `Vault::dir_name`, the IO script's word match and allow, the regex with lifetimes, `mod storage`'s allow, slice splits, §6/§7/§13 wording, the 014 and 017 references (J3-A1–J3-A3, J3-A8–J3-A21, J3-B10, J3-C5, J3-C7, J3-C9–J3-C17, J3-C19, J3-D14–J3-D18, J3-D20–J3-D27) | Low | Corrected in the specs, §4, §7 and §13 |

Not changed on purpose in round 3: public newtypes for `channel_id`, `server_id` and `pk` (J3-C18) are left to spec 040-uniffi, which maps the two array sizes once as custom types.

Round 4: 53 findings (J4-A1–J4-A14, J4-B1–J4-B8, J4-C1–J4-C15, J4-D1–J4-D16), no Blocker, 1 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J38 | The test doubles could not be observed once `Channel` or `Device` had taken them, could not fail late or count commits, and `FailingStore<S>` did not type-check over a `Box<dyn Store>` (J4-C1, J4-C3) | High | `MemoryStore`/`MemoryVault` as `Clone` handles with `reopen` and `commits`; a shared `Faults` handle with `fail_at`, `poison_after`, vault faults and `last_committed`; `state_eq` and `records_eq`; the rust skill allows `Arc<Mutex<_>>` in `testing` only (spec 020) |
| J39 | A `LogFull` stall ended only when the user sent; the 1 MiB compaction still amplified writes about 60×; publishing went on after the own-key alert (J4-B1, J4-B3, J4-B5, J4-D1) | Medium | The `Device` compacts stalled channels on the tick; the headroom compaction at most once every ten minutes; nothing more published after `check_own_key` fires (specs 021 R18, 027 R12, 028 R10) |
| J40 | A server could date a message just inside the display window to hide it with no gap; the display rule skipped the own-key branch (J4-B2, J4-B6) | Medium | Display time `r = max(received_at, sent_at − 360 000)` for peers, after `open`; the own-key branch follows its own rules (spec 021 R10, R26, spec 023 R2) |
| J41 | `synced_at` moved only at `ok`, so a long quiet connection could be staged as truncation; a future clock froze it; a truncation found before a lost connection was never reported (J4-B4, J4-B8, J4-D4) | Medium | `synced` on every tick while subscribed, committed when half a TTL old; `synced_at = now`, a future value ignored; the pending truncation kept by the channel until an `ok` takes it (specs 021 R20, R24, 028 R8, R9) |
| J42 | An `ack` lost to a lock and then expired showed `NotDelivered` for a delivered message; an always-late `ack` of the retirement republished every tick (J4-D2, J4-D3) | Medium | An echo proving in-time storage re-acknowledges an entry already reported not delivered; a late `ack` of the current retirement holds it until its next re-seal (specs 021 R13, 023 R3, 028 R12) |
| J43 | Recovery after a poisoned commit could not find the `ClientRef`; direct calls had nowhere to return reopen events; reconnection after a network drop and plans of refused channels were undefined; any settings setter released the gate (J4-C4, J4-D5, J4-D6, J4-D9, J4-D10, J4-B7) | Medium | `send_counter` and `outbox_ref`; reopen events queued for the next `on_tick`; the client repaints after `StorageFailed`; peer-closed sockets reopen with backoff, fully refused plans are left out; only `acknowledge_settings` and `set_socks5_proxy` clear the gate (specs 021 R33, 027 R2, R9, R11, R14) |
| J44 | `Message` carried the crate-internal `Content`; stale "021 R…" references after the renumbering; `duplicate` declared in the later spec; 028 and 023 relying on 025 without depending on it; `MAX_LABEL` in the later spec (J4-A1, J4-A2, J4-A5–J4-A7, J4-A9, J4-C2, J4-C10, J4-D7) | Medium | `MessageContent`; references corrected; `duplicate` in 020, `MAX_LABEL` in 022; 028 depends on 025; 023's test uses the builders |
| J45 | Small ones: `R3`'s exceptions, `load` without `state.bin`, a test for 021 R1, T order, `remove_broken` failures, `commits = 0`, citations, the expiry index, `purge_expired` with nothing expired, the tick's `expire_outbox` split, the seeded exit test, the live-name set, stored-config decode errors, cfg gating, `Frame` without `PartialEq`, long calls off the UI thread, slice sizes, cleaning every name handed out, row placement, `ChannelFull` per channel, unnamed refusals, discarding stale subscribes (J4-A3, J4-A4, J4-A8, J4-A10–J4-A14, J4-C5–J4-C9, J4-C11–J4-C15, J4-D8, J4-D11–J4-D16) | Low | Corrected in the specs and in ADR 0037's consequences |

Round 5: 53 findings (J5-A1–J5-A15, J5-B1–J5-B6, J5-C1–J5-C17, J5-D1–J5-D15), no Blocker, 2 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J46 | While the settings gate was up, any setter wrote a settings file without the lost proxy, so the next unlock connected directly (J5-D1) | High | While the gate is up, only `acknowledge_settings` and `set_socks5_proxy` write the file; the other setters change memory only (spec 027 R2) |
| J47 | A server that queues a whole backlog at once hits the 4 MiB send-queue close, and every reconnect repeats it (J5-D2) | High | The backlog is written at the pace the socket drains and is bounded per subscription, outside the close rule (spec 028 R4; spec 030 inherits it) |
| J48 | The re-acknowledgement of a not-delivered entry could not find its `ClientRef`, and a replayed echo wrote a record every time (J5-B1, J5-B2, J5-D6) | Medium | Kept signatures carry the entry's `client_ref`; the re-acknowledgement happens once (spec 020 key 13, spec 021 R13, R15) |
| J49 | A future `sent_at` pinned a message to the bottom of the list, and live and repainted rows disagreed (J5-B4, J5-A3, J5-D5, J5-A11) | Medium | Rows ordered by `received_at` clamped to the decrypt time, carried by `Received` and `Message`; the display time bounds only the expiry (specs 021 R11, R12, 023 R2) |
| J50 | After the own-key alert stopped publishing during a stall, the retirement could not leave; a server that never sends `ok` hid a truncation; a channel could wait for `ok` for ever (J5-B3, J5-B5, J5-D3) | Medium | A regeneration on a stopped channel asks for a reconnect; `HistoryTruncated` is produced when truncation is decided; no `ok` within a minute → reconnect, and a `rate_limited` subscribe is queued again (specs 027 R9, 028 R8, R9, R16) |
| J51 | The periodic purge and the stalled-channel compaction had no `Channel` method; `synced_at` could lag half a TTL at lock or stay in the future; §4 did not list the new step 0 and step-6 duplicates (J5-A2, J5-A5, J5-B6, J5-D4, J5-C6) | Medium | `purge_due` and `relieve_headroom`; `flush` at lock, a capped and future-proof `synced_at` rule; §4 steps 0 and 6 (specs 021 R18, R20, 023 R5, 027 R12, R24) |
| J52 | Oversized PR slices; `poison_after` ambiguous across a shared handle; an infeasible collision test (J5-C1–J5-C3) | Medium | More slices and a `testing/` layout; poisoning belongs to one store instance and counts from arming; precomputed collision fixtures |
| J53 | Small ones: `MAX_NAME` in 020 (026's duplicate rule removed), `PeerId` in 021, `MessageContent` in 027's list, builder notes on tests of later states, test renumbering in 021, `commits = 0`, the own record's grace, the settings range and `seal`, fuller frame vectors, the save retry, `Io`-broken import retry, `.leaving` leftovers, unnamed `bad_blob`, `on_disconnect` on every close, one repaint list, a peers-changed flag, `Sent` with its `Message`, `probe_plan` on a bad URL, the compaction timer, directory `fsync`s at creation, stray entries in `channels/`, crash helpers and temporary directories, the exit-test schedule, `LogRecord` without placement fields, the fuzz reach of sealed `open`s (J5-A1, J5-A6–J5-A10, J5-A12–J5-A15, J5-C4, J5-C5, J5-C7–J5-C17, J5-D7–J5-D15) | Low | Corrected in the specs |

Round 6: 27 findings (J6-A1–J6-A12, J6-B1–J6-B4, J6-C1–J6-C6, J6-D1–J6-D5), no Blocker, 1 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J54 | The one-key name comparison of round 1 let "ALICE" pass next to "Alice": the first skeleton turns the capital I into an l before lowercasing (J6-C1, checked against `confusables.txt`) | High | Two keys per name — skeleton, lowercase, skeleton; and lowercase, skeleton — and a collision when either matches (spec 022 R4, ADR 0036 amended before its first commit, §7). For the human reviewer to confirm |
| J55 | A thief's overtaking message plus a lost `ack` let the round 5 re-acknowledgement mark as delivered a message every receiver rejected (J6-B1) | Medium | No re-acknowledgement once `own_key_used_elsewhere` is set (spec 021 R13) |
| J56 | Ordering by the clamped server time let a server bury a message a TTL back, and a future-dated `ack` pinned one's own row; one's own row used the raw server time (J6-B2, J6-B3, J6-D1) | Medium | Peer rows at `min(r, now)`, own rows at the `ack`'s time clamped to `now`; `acked` takes `now` (specs 021 R11, R13, R17, 023 R1, R2, 028 R12) |
| J57 | The gap baseline after truncation was lost at the next lock, so expired messages read as a deletion days later (J6-D2) | Medium | `truncated_before` persisted (state key 18); a sender last seen before it counts no gap (specs 020, 021 R24) |
| J58 | Slices untestable in their own order or over 400 lines; the round 5 own `purge_at` not carried into 023 R1; a 022 test and a 021 test relying on later specs (J6-C2, J6-C3, J6-C4, J6-A1–J6-A3, J6-D4) | Medium | Slices reordered and split; 023 R1 cites 021 R26; the tests moved to the specs that own the behaviour |
| J59 | Small ones: the server's bound on held pushes closes and never drops, `nonce_expired` resets only the named channel, the `ok` wait in Limits, the `Io` retry drops the broken entry, `regenerate_identity` gets its reopen events, T01 and T10 values, `commits = 0`, the framing owned by `store`, 011's `RecordError` sentence, §4/§7 re-seal wording, §7 label size, 017's record owners (J6-A4–J6-A12, J6-B4, J6-C5, J6-C6, J6-D3, J6-D5) | Low | Corrected in the specs, §4 and §7 |

Round 7: 24 findings (J7-A1–J7-A7, J7-B1–J7-B3, J7-C1–J7-C7, J7-D1–J7-D7), no Blocker, 1 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J60 | Two name keys still let "ALlCE" (a small L for the I) and "0LIVIA" pass next to "Alice" and "Olivia": collision under case and confusables is not transitive (J7-B2, checked against `unicode-security` 0.1.2) | High | One key again, with a final fold of `i` into `l` after the second skeleton; every listed pair collides and "Alice"/"Alicia" does not (spec 022 R4, ADR 0036 amended before its first commit, §7). For the human reviewer to confirm, with J54 |
| J61 | A past-dated `ack` hid one's own message and buried it a TTL back (J7-B1) | Medium | The acked time is clamped between `sent_at − 360 000` and `now` (spec 021 R13, R17; spec 023 R1) |
| J62 | A foreign own-key blob seen only through `check_own_key` removed no overtaken entries, and a second one did not stop publishing (J7-D2) | Medium | `check_own_key` applies R14's removal within the reserve and returns `true` for every foreign blob (spec 021 R19, spec 028 R10) |
| J63 | Truncation used the skew margin although both times are local, so short-TTL unlocks showed false gaps; a persisted boundary silenced a quiet sender's later gaps for ever; re-queued subscribes re-decided truncation (J7-D1, J7-B3, J7-D6) | Medium | `last + ttl_ms < now`; `truncated_at` stored, `None` only for a message within a TTL of it, later gaps marked `spans_truncation`; one decision per channel per connection (specs 020 key 18, 021 R24, 028 R8) |
| J64 | An unsolicited `nonce_expired` would reconnect every minute; one channel's long backlog tripped another's `ok` timeout (J7-D3, J7-D4) | Medium | The server sends `nonce_expired` only in reply to a late `subscribe`, naming it; the `ok` timeout counts silence on the whole connection (spec 028 R4, R9) |
| J65 | The framing move of round 6 was half applied, so the file checks had no home; PR slices still untestable in their order or over 400 lines (J7-A1, J7-A2, J7-C1–J7-C4) | Medium | `open`/`seal` take `nonce ‖ box`; R4, R7 and their tests split between `store` and `core`; slices reordered and `testing` split in three (specs 020, 021, 022, 027, 028) |
| J66 | Small ones: `truncated_at` among the pending values and in `flush`, `acked`'s `now` in R16, the fuzz target's name, §4/§7 rendering set, 017's frame owner, U+1160 in T05, the `Io` retry's new reason (J7-A3–J7-A7, J7-C5–J7-C7, J7-D5, J7-D7) | Low | Corrected in the specs, §4 and §7 |

Round 8: 30 findings (J8-A1–J8-A12, J8-B1–J8-B3, J8-C1–J8-C6, J8-D1–J8-D9), no Blocker, no High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J67 | An i or a dotless ı with a combining dot still escaped the name key (J8-B1, checked with the real crates) | Medium | Canonical decomposition and removal of combining marks after the fold (spec 022 R4, ADR 0036 before its first commit, §7). With J54 and J60, for the human reviewer |
| J68 | Under a full log, `check_own_key` skipped the send-counter bump and its removal could hit `LogFull` and take the alert with it; overtaken old-key entries were removed after the new key was stolen, and not removed when the old key's thief kept writing (J8-B2, J8-B3, J8-A1, J8-C6, J8-D2, J8-D3) | Medium | R19 applies R14's counter bump and removal, falling back to the flag and counter alone on `LogFull`; removals skip entries under the retired key, and a thief's old-key blob removes the overtaken old-key entries at step 5 (spec 021 R3, R9, R14, R19) |
| J69 | The session could not build a clamped `Delivered`, a stopped channel's outcomes waited for a later `decrypt`, the stall begun by a thief's blob did not stop publishing, and a regeneration on a stopped channel had no reconnect rule in 028 (J8-D4, J8-D1, J8-D8, J8-A6) | Medium | `acked` returns an `Outcome` with the clamped time; outcomes drained after `check_own_key` too; a stopped channel expires on the tick and a regeneration reconnects (spec 021 R17, spec 028 R10–R12, spec 027 R9) |
| J70 | Senders without a peer record lost their unknown mark and warnings; a retired label did not count for `claims_name_of`; an `ack` dated before `sent_at` in a short channel gave `Delivered` for a message receivers reject (J8-D5, J8-D6, J8-D7) | Medium | `Message::stranger` computed by the core; retired labels count; `Delivered` only when the clamped time is in the window and still displayable (specs 022 R13, 023 R3, 021 R17) |
| J71 | PR slices whose tests need a later slice, again, across 020, 021, 022, 027 and 028 (J8-A3–J8-A5, J8-A9, J8-A10, J8-C1–J8-C5) | Medium | One rule in every slice list: each test clause lands in the slice that implements the last behaviour it needs; the specific moves of R5, R26, T09, T14 stated |
| J72 | Small ones: R5 split between `store` and `core`, R6 leaving the verdict to R7, 028 T08/T09 for the round 7 rules, `commits = 0` on two own-key rejections, `sent_at` in `NotDelivered` for a row no longer listed (J8-A2, J8-A7, J8-A8, J8-A11, J8-A12, J8-D9) | Low | Corrected in the specs |

Round 9: 30 findings (J9-A1–J9-A11, J9-B1–J9-B6, J9-C1–J9-C4, J9-D1–J9-D9), no Blocker, 1 High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J73 | The round 8 step-5 removal also removed the pending `key_retired`, which an echo of a superseded copy could trigger with an honest server, leaving the retirement pending for ever (J9-A1, J9-B3) | High | Step 5 removes only ordinary entries under the retired key, only for a blob that is not stale, with outcomes queued (spec 021 R9; J9-A2, J9-B5, J9-B6) |
| J74 | `NotDelivered.sent_at` had no source; the echo re-acknowledgement bypassed round 8's displayability rule; `check_own_key` did not do step 5 during a stall; the stop withheld the retirement and old-key entries too, and did not cover `ok` or `encrypt` (J9-A3, J9-A4, J9-A8, J9-B2, J9-B4, J9-C1, J9-D3–J9-D7) | Medium | `sent_at` in `Outcome`, `OutboxStep`, `expire_outbox` and `abandon`; R13 applies R17's conditions; R19 applies step 5 for the retiring key; a stopped channel withholds only ordinary entries of the current key, at `ok` and after `encrypt` too (specs 021, 028) |
| J75 | Two more pixel-identical names escaped the key: a dotless ȷ with a combining dot and a trailing U+2800 (J9-B1, J9-D1) | Medium | `ȷ` folded into `j`; blank-rendering characters listed in `INVISIBLE`; the name comparison's residual stated in spec 022's Security, so that new look-alikes are additions to the table, not design breaks (spec 022, ADR 0036 before its first commit) |
| J76 | After `StatusChanged` nothing said to re-read `messages`, so a vanished record's warnings were lost (J9-D2) | Medium | The re-read list of spec 027 R14 covers `StatusChanged` |
| J77 | Small ones: T10/T13/T19 cases, `acked`'s public-API sentence, the vectors README's `commits = 0` exception, R5's halves in the slice list, a single-row `message`, `peers`/`messages` returning `Result`, `MemoryStore` applying R16, a new peer never evicting itself, `own_display_name` in `ChannelInfo` (J9-A5–J9-A7, J9-A9–J9-A11, J9-C2–J9-C4, J9-D8, J9-D9) | Low | Corrected in the specs |

Round 10: 18 findings (J10-A1–J10-A7, J10-B1, J10-B2, J10-C1–J10-C3, J10-D1–J10-D6), no Blocker, no High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J78 | The stopped state had no mechanism: no `outbox` call, and no way to tell which blobs to hold (J10-A1, J10-C1, J10-D1) | Medium | `outbox(…, withhold_current)` hands out only the retirement and old-key entries; the session calls it for stopped channels (spec 021 R22, spec 028 R9, R10, R14) |
| J79 | A thief's own-key blob dated too far ahead skipped the removal of overtaken entries, which later readers then reject (J10-B1) | Medium | Removals gated on the past side of staleness only; the counter rule of ADR 0029 unchanged (spec 021 R9, R14, R19) |
| J80 | A refused entry re-sent after a later one of the same channel reaches every receiver as `Replay` but is acked `Delivered` (J10-D2) | Medium | An in-time `ack` of an entry removes every lower ordinary entry of the same key as not delivered (spec 021 R17) |
| J81 | The client was not told to re-read `gaps`; a verified peer without a label escaped the collision checks (J10-D3, J10-D4) | Medium | `gaps` in the re-read list after `StatusChanged`; `verify` requires a label (specs 027 R14, 022 R8) |
| J82 | Small ones: `Outcome.sent_at` optional, R22's text, `message` infallible, `own_display_name` accessor and cleaning, §7's key and invisible set, §4's exception list, `all_commits`, the peer record kept while a copy can be accepted (so the pair check holds against republished expired blobs), the re-acknowledgement's `server_id`, the no-channel settings residual (J10-A2–J10-A7, J10-B2, J10-C2, J10-C3, J10-D5, J10-D6) | Low | Corrected in the specs, §4 and §7 |

Round 11: 22 findings (J11-A1–J11-A7, J11-B1–J11-B4, J11-C1–J11-C6, J11-D1–J11-D5), one High, overlapping heavily. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J83 | Every consumed message set the peers-changed flag, so every push made the client re-read every list (J11-D1) | High | The flag is set only by a peer created or removed, a change of label, verified, muted, retired or name, or a gap change; one re-read per step (specs 021 R1, 028 R13, 027 R14) |
| J84 | A peer record lapsed a whole TTL before copies of its blob stopped being accepted, so a server could revive an expired message (J11-B1) | Medium | Peer `purge_at` second term `sent_at + 2·ttl_ms + 360 000` (spec 021 R26, T26) |
| J85 | `check_own_key` still gated removals on full non-staleness; a blob dated a decade ahead removed delivered entries (J11-A2, J11-B2, J11-B3, J11-C3, J11-C4, J11-D3) | Medium | One "within reach" test in R14 (no `sent_at`, or past side fresh and at most `2·ttl_ms + 360 000` ahead), used by R9, R14 and R19; counter bump still needs not stale; tests |
| J86 | Outcomes queued by `acked` were not drained (J11-A3, J11-C1, J11-D2) | Medium | Spec 028 R11 drains after `acked`; T12 |
| J87 | `verify` needing a label left no 12-word path for a new key whose name an unverified old key holds; its admission check was dead (J11-A4, J11-C2, J11-D4) | Medium | `verify(peer, label, now)`: a label for an unlabelled peer, rules of R7 with the target verified, admission check, all or nothing (specs 022 R8, 026 R4, 027, `docs/spec.md` §9) |
| J88 | An echo of an entry removed by a later entry's `ack` was re-acknowledged `Delivered` (J11-D5) | Low | Spec 021 R13: no re-ack when an acked record names a later own message of the same epoch |
| J89 | Small ones: T10's `purge_at`, R8's `sent_at`, the testing builders in T09/T19/T22, 025 R4's `outbox` signature, `None` from `message` → `Internal`, the server's publish order in the contract (J11-A1, J11-A5–A7, J11-B4, J11-C5, J11-C6) | Low | As listed (specs 021, 025, 027, 028 R4, T04) |

Round 12: 18 findings (J12-A1–J12-A8, J12-B1–J12-B3, J12-C1, J12-D1–J12-D6), no High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J90 | A peer's whole message stayed on disk about two TTLs, and a far-dated flood stalled a channel up to three (J12-B1) | Medium | A small seen record (`server_id`, `sender_pk`, `counter`) carries the long `purge_at` and the step-6 checks; the message record goes at its display expiry (specs 020 log schema and vectors, 021 R9, R11, R26, T10, T26) |
| J91 | Direct calls never raised `StatusChanged`, and an offline channel never consumed the peers-changed flag (J12-D2, J12-B3) | Medium | The `Device` compares status and the flag around every direct writer, and `on_tick` consumes the flag of unconnected channels; `own_display_name` sets the flag (specs 027 R14, 021 R1, 028 T13) |
| J92 | One's own delivered message keeps its plaintext up to one TTL after its row goes (J12-D1) | Medium | Documented in 023 Security and raised as an open question with a recommendation; 023 R1's parenthetical corrected |
| J93 | The "within reach" bounds ignored members' clock skew (J12-B2) | Low | Both bounds widened by the margin (spec 021 R14, T09, T14) |
| J94 | A republished foreign own-key blob wrote a second record and row (J12-D3) | Low | After the echo rule, a seen record from one's own key with the same counter → `Replay` (spec 021 R9, T09) |
| J95 | Small ones: T10's `purge_at`, `Unreadable` with a `sent_at`, T09's stale case, the guard's key, `Internal` vs "MUST return `Ok`" and when `message` is read, T01's label clause moved to 022 T10, the `acked` drain tested in T11, 014/022 on `verify_scanned`, retired labels in `label_collides`, the imported `created_at` margin, `last_seen` not live (J12-A1–A8, J12-C1, J12-D4–D6) | Low | As listed (specs 014, 020, 021, 022, 023, 027, 028) |

Round 13: 11 findings (J13-A1–J13-A3, J13-B1, J13-C1, J13-C2, J13-D1–J13-D3), one Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J96 | One's own `pk_u` was not excluded from the room check, peer creation or a stranger's retirement, so 50 muted unknowns swallowed the own-key alert (J13-B1) | Medium | "Other than one's own `pk_u`" in specs 021 R9, 022 R1, 024 R2, 026 R2; tests in 021 T14 and 026 T02 |
| J97 | The own-key seen record lapsed six minutes before R14 stops accepting a copy; R13 and §4 lacked the J94 step (J13-A1, J13-A2) | Low | Its second term `sent_at + 2·(ttl_ms + 360 000)`; R13 and §4 name the check; T26 |
| J98 | A first commit poisoned after its rename left a phantom channel; an R14 broken entry did not say which channel (J13-D2, J13-D3) | Low | Create and import reopen once and adopt a standing state; `BrokenChannel` gains optional `channel_id` and name (spec 027 R4, R14, T04, T14) |
| J99 | Small ones: T26's scenario, `purge_expired` among the direct writers, `on_tick`'s flag producing the event, the no-`sent_at` residual (J13-A3, J13-C1, J13-C2, J13-D1) | Low | As listed (specs 021 R26, Security, T26; 023 Security; 027 R14, T14) |

Round 14: 10 findings (J14-A1, J14-A2, J14-B1, J14-C1, J14-C2, J14-D1–J14-D4), two Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J100 | A compaction failing on every call (a disk with less room than the log) was retried and reopened every second, keeping every channel of the run disconnected (J14-D1) | Medium | Every compaction attempt counts for the ten-minute limit; a failed relief returns `LogFull`; `purge_due` holds off for ten minutes; a failed purge or relief raises `StorageFailed` without reopening (specs 021 R18, T18; 023 R5; 027 R15, T15) |
| J101 | A backlog whose every push raises `StatusChanged` made the client re-read every list per push (J14-D2) | Medium | The client marks the channel and re-reads at most once a second, at its tick (spec 027 R14) |
| J102 | Under a full log, a stale foreign `key_retired` made the channel read-only, unlike `decrypt` (J14-B1) | Low | `read_only` goes with the counter bump, only when not stale (spec 021 R19, T19) |
| J103 | Small ones: which name `BrokenChannel` carries, the flag test that could not be written (the flag now starts set at load), 022 R1's own-key test, create's retry returning which error and a failed retry going to `broken`, an unreadable `settings.bin` blocking every unlock (J14-A1, J14-A2, J14-C1, J14-C2, J14-D3, J14-D4) | Low | Specs 021 R1, T01; 022 T01; 027 R1, R4, R14, T01, T04, T14 |

Round 15: 17 findings (J15-A1–J15-A5, J15-B1–J15-B3, J15-C1–J15-C5, J15-D1–J15-D4), five Medium, overlapping. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J104 | A failed purge or relief was told both to reopen and not to; a poisoned relief on a receive-only channel stalled it for the session; any reopen reset the ten-minute hold; `relieve_headroom`'s result undefined (J15-A1, J15-B1, J15-C3, J15-D1) | Medium | A failed purge or relief raises `StorageFailed` and reopens; every reopen carries `last_compaction()`; `relieve_headroom` returns `Ok(true)`, `Ok(false)` or the error (specs 021 R18, Interface, T18; 027 R14, R15, T15) |
| J105 | Create's retry could not tell "no state" from `Corrupt`, and T04's clause could not be produced (J15-A2, J15-C1) | Medium | The retry calls `Store::load` first; `Faults` gains `fail_create_at(n)` and `fail_compactions(on)` (specs 027 R4, T04; 020 testing module) |
| J106 | A local writer could make the device save proxy-less settings by hiding the channels for one unlock; the first save could come after the first channel (J15-B3, J15-D3) | Low | A fresh install saves nothing until the user's first write; create and import save before `Vault::create`; the tick retry removed (spec 027 R1, R4, R12, T01, T12, Security) |
| J107 | A relief that cannot restore room still rewrote the log; a failed write left its temporary file taking the space (J15-C4, J15-D2) | Low | Relief only when enough has expired to restore room; a failed commit or compaction deletes its temporary file (specs 021 R18, T18; 020 R11, T11) |
| J108 | Small ones: `read_only` in R19's fallback, the ten-minute hold tested in 023 and 021, an empty run left in the plan, T01's duplicate (J15-A3–A5, J15-B2, J15-C2, J15-C5, J15-D4) | Low | Specs 021 R19, T19, T18; 023 T05; 027 R10, T10, T01 |

Round 16: 13 findings (J16-A1–J16-A5, J16-B1–J16-B4, J16-C1, J16-D1–J16-D4), one Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J109 | A channel readable but not writable looped through reopen and reconnect, keeping the rest of its run from subscribing (J16-D1) | Medium | A second `Io` within ten minutes of a reopen moves the channel to `broken` and out of its run (spec 027 R14, T14) |
| J110 | A relief poisoned inside `encrypt`/`decrypt` returned `LogFull`, stalling a receive-only channel ten minutes (J16-B1, J16-D2) | Low | A failed compaction there returns its error, so R14 reopens at once (specs 021 R18, T18; 027 T15) |
| J111 | Texts still gave the old 1 MiB relief threshold; `purge_due` after a clock set back (J16-A1, J16-B3, J16-B4, J16-C1) | Low | Specs 021 R18, Limits, T18; 023 R5, T05 |
| J112 | Small ones: a T18 clause needing spec 023 moved there, `state.bin.tmp` deletion tested, a saved setting kept after a failed create, T15's poisoned-compaction path, the per-unlock bound documented, a first commit cut before its header, `flush` attempting every channel (J16-A2–A5, J16-B2, J16-D3, J16-D4) | Low | Specs 020 R11, R13, R19, T11, T13, T19; 021 Security; 023 T05; 027 R1, R24, T15, T21, T24 |

Round 17: 23 findings (J17-A1–J17-A7, J17-B1–J17-B4, J17-C1–J17-C6, J17-D1–J17-D6), four Medium, overlapping. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J113 | The J109 rule contradicted R15's reopens and T15, had no time for calls without `now`, no strict window, no clock-set-back rule, no double, and did not drop the store (J17-A1, J17-A3, J17-C1–C3, J17-C6, J17-D2, J17-D3, J17-D5) | Medium | Only R14's own reopens count, less than 600 000 ms ago, measured with the largest `now` seen; a later recorded time counts as not within; the `Channel` is dropped; `Faults::fail_commits` (specs 027 R14, T14, Limits; 020 testing module) |
| J114 | A channel broken by a full disk never came back without an unlock (J17-D1) | Medium | `on_tick` retries `Io`-broken entries every ten minutes (spec 027 R12, T14) |
| J115 | R9 and §4 step 0 still said every headroom failure gives `LogFull`; `send` had no outcome when R14 went straight to `broken` (J17-A2, J17-A4, J17-C5, J17-D4) | Low | R9 and §4 name the compaction error; the `Device` reopens once to read a `send` or regeneration outcome (specs 021 R9, 027 R9, 028 R10, `docs/spec.md` §4) |
| J117 | One poisoned store could be counted twice in one step and go to `broken` (J17-B1; J17-B2–B4 as J113, J115) | Low | Only failures of the instance the reopen handed out count, once per step (spec 027 R14, T14) |
| J116 | Small ones: the size rule would erase a compacted channel that lost its state, and the doubles did not follow it; the per-unlock bound's exceptions; deletions at open not best effort (J17-A6, J17-A7, J17-C4, J17-D6) | Low | Specs 020 R12, R13, R19, T13, T19, testing module; 021 Security |

Round 18: 19 findings (J18-A1–J18-A9, J18-B1–J18-B3, J18-C1–J18-C3, J18-D1–J18-D4), five Medium, overlapping. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J118 | Dropping a channel to `broken` after two `Io` failures let one leaked config, by filling the disk, empty the whole channel list, hide all history and block `leave` of the flooded channel (J18-B1) | Medium | The channel is reopened and marked `write_failed` instead: listed, readable, `leave` working, out of its run; `on_tick` puts it back every ten minutes, counted as an R14 reopen (spec 027 R9, R12, R14, `ChannelInfo`, Limits, T12, T14) |
| J119 | R12's retry could not open an entry with no `channel_id`, had no clock rule, and a restored channel was not re-listed by the client (J18-A1, J18-A2, J18-A4, J18-B2, J18-B3, J18-C1, J18-C2, J18-D1, J18-D4) | Medium | Retry only entries with a `channel_id`, which a failed import retry now fills in; a later time reset to `now`; the client re-reads `channels()` and `status()` after `StatusChanged` for a channel it does not list and after an import (spec 027 R5, R12, R14, T05, T12) |
| J120 | Slice d2 far over 400 lines (J18-C3) | Medium | Split into d2a and d2b (spec 027 slices) |
| J121 | Small ones: §4 step 0 and 021 Security on R19 after a failed compaction, R12's test in T12, the per-unlock bound's list, a `Corrupt` recorded as `Io`, T13's 9-byte cases, R14's `.new` deletion best effort, a passing `Io` on settings overwriting the proxy (J18-A3, J18-A5–A9, J18-D2, J18-D3) | Low | Specs 020 R14, T13, T14; 021 Security; 027 R2, R14, T02, T12; `docs/spec.md` §4 |

Round 19: 17 findings (J19-A1–J19-A5, J19-B1–J19-B3, J19-C1–J19-C3, J19-D1–J19-D6), one High and four Medium, all but two in the `write_failed` state of round 18. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J122 | A `write_failed` channel was reloaded every second by the tick's writers; its failures had no rule; direct writers never cleared it (J19-A1, J19-C1, J19-D1, J19-D2, J19-D3, J19-A5) | High | While marked: no tick writers, session and tick failures change nothing, a failing direct writer reopens once silently for R9, a succeeding one clears the mark; event counts stated (spec 027 R12, R14, T14) |
| J123 | On a full disk the own-key alert never arrived and the pending retirement never left, since a marked channel left its run (J19-B1) | Medium | A marked channel stays in its run in the receive-only stall of 028 R10; `check_own_key` keeps the flag in memory when its commit fails (specs 021 R19, T19; 027 R10, R12, R14, Limits; 028 R10, Interface, T10) |
| J124 | "Its run" undefined on the way back; R12's clock rule contradicted T12 (J19-A2, J19-A3, J19-A4, J19-C2, J19-D4) | Low | Resolved by staying in the run; a later recorded time counts as passed (spec 027 R10, R12) |
| J125 | Small ones: a flooded `Io`-broken channel could not be removed; `leave` does not make the retries due; `set_socks5_proxy` after a passing `Io` reset other settings; gate-time setter changes lost on re-read; `fail_*` switches; a poisoned direct write on a marked channel; `BrokenChannel`'s comment (J19-B2, J19-B3, J19-C3, J19-D5, J19-D6) | Low | Specs 027 R2, R3, R14, Interface, T02, T03, T14; 020 testing module |

Round 20: 29 findings (J20-A1–J20-A11, J20-B1–J20-B3, J20-C1–J20-C8, J20-D1–J20-D7), thirteen Medium, overlapping, all on the full-disk path of round 19. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J126 | The own-key alert could still be lost on a full disk: the first failing push never reached `check_own_key`, the mark was forgotten at reconnect or a new plan, a store error before the mark kept pushes from `check_own_key`, and every reopen dropped the in-memory flag (J20-A1, J20-A3, J20-A4, J20-B1, J20-B3, J20-C1, J20-C2) | Medium | A push whose `decrypt` fails with a store error goes to `check_own_key` first; marks survive reconnects and are set on every new `Session`; the mark overrides the dropped state; reopens carry the flag (`hold_own_key_alert`) (specs 021 Interface; 027 R14, T14; 028 R5, R10, Interface, T10) |
| J127 | The pending `key_retired` did not leave on a full disk once its minute had passed, nor behind a stale entry (J20-B2, J20-C3) | Medium | A failing `outbox` commit still hands out, from memory, what needs no change, stale entries counted as gone, the retirement re-sealed for that call only (spec 021 R22, `OutboxStep::store_error`, T22; 028 R10, T10) |
| J128 | A marked channel republished acked entries every tick; clearing resumed `decrypt` on the same connection (J20-A2, J20-C4) | Medium | A failed `acked` holds its `client_ref`; the stall lasts until `on_disconnect` (spec 028 R10, T10) |
| J130 | An R15 reopen after a clearing restarted the count, giving three `StorageFailed` per cycle; a marked channel could still commit `synced_at` (J20-D6, J20-D7; J20-D1–D5 as J126–J128) | Low | R15's reopens pass the R14 record on; no cursor or `synced` commit while marked (specs 027 R14, T14; 028 R10) |
| J129 | Small ones: event counts and "in every case", the session's own `StorageFailed`, `synced` while stalled, R19's result, which writers clear a mark, the Limits row, the `leave` clause in T03, the clock rule for clearing (J20-A5–A11, J20-C5–C8) | Low | Specs 021 R19; 027 R3, R14, Limits, T03, T14; 028 R9, R10 |

Round 21: 24 findings (J21-A1–J21-A8, J21-B1, J21-B2, J21-C1–J21-C6, J21-D1–J21-D8), one Medium, all on the full-disk path; pass C judged the machinery out of proportion and sketched a simpler one, which was adopted. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J131 | The full-disk handling had grown per-instance counting, first/marking/silent reopens, records passed between R14 and R15, and a clearing that reconnected the run every ten minutes to refetch up to 64 MiB on a disk still full (J21-C info, J21-D1, J21-D2, J21-D8, J21-A1, J21-A6) | Medium | Replaced by one rule: the first store failure reopens once and marks the channel `write_failed` (receive-only stall, no `Reconnect`); R12 probes it with a state-only commit after 60 000 ms, then every 600 000 ms, and clears it with `Reconnect` only when that commit succeeds; a direct writer returning `Ok`, `leave` or `remove_broken` makes the probe due (specs 027 R12, R14, R15, Limits, T14, T15; 021 R20 `probe`, R22, R32; 028 R10) |
| J132 | A carried flag gave a freshly regenerated key a false alert; an alert held in memory was lost at lock (J21-B1, J21-B2, J21-C1, J21-D7) | Low | The flag is carried only onto the same own `pk_u`; `flush` persists it; the residual documented (specs 021 R20, Security; 027 R14, T14) |
| J133 | Small ones: `hold_own_key_alert` defined, the two exceptions to R2, `synced` at `ok` when stalled, stopping on the `Io` path, the retirement hold with memory-only re-seals, 025 R4's exception and the T22/T04 split, events of a failing `send`, `not_delivered` under `store_error`, acks held marked or not (J21-A2–A5, J21-A7, J21-A8, J21-C2–C6, J21-D3–D6) | Low | Specs 021 R19, R22, T19, T20, T22; 025 R4, T04; 028 R9, R10, R12, R16, T10 |

Round 22: 17 findings (J22-A1–J22-A6, J22-B1–J22-B4, J22-C1–J22-C3, J22-D1–J22-D4), seven Medium, overlapping, all on the probe design of round 21. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J134 | A state-only probe does not prove the failed write works: a full channel reconnected and refetched every eleven minutes, and a disk with room for the state but not a message probed every minute (J22-D1, J22-D2) | Medium | With `storage_full` the probe clears the mark without `Reconnect`, back into the `LogFull` stall; a failure within ten minutes of a clearing probes after 600 000 ms (specs 027 R12, R14, T14, T15; 028 R10) |
| J135 | An `outbox` failure on an unmarked channel never reached R14; old-design clauses in T14 (J22-A1, J22-A2, J22-C1) | Medium | A `store_error` is reported in `failed`, marked or not; T14 rewritten (specs 028 R14, T14; 027 T14) |
| J137 | On an unwritable disk only the own-key flag was held: the counter bump and `read_only` were lost once the thief's blob left the server, and later messages read `Delivered` while nobody accepted them (J22-B2; J22-B1 as J134) | Medium | The fallback holds the counter bump and `read_only` in memory too; `hold_own_key_alert` carries all three over a reopen (specs 021 R19, R20, Interface, T19; 027 R14) |
| J138 | A failed `abandon` on a marked channel republished its entry every tick (J22-B4; J22-B3 as J135) | Low | A failed `abandon` holds the `client_ref`; `NotDelivered` only on `Ok(Some)` (spec 028 R16) |
| J136 | Small ones: R9 vs a marked channel, the Limits row, the session's `expire_outbox` on a marked channel, T03's wording, a citation, the session's events after a store error, a reopen to `broken` with no event, stale entries never reported while marked, `Reconnect` for an unconnected channel (J22-A3–A6, J22-C2, J22-C3, J22-D3, J22-D4) | Low | Specs 021 R22, Interface, T22; 027 R9, R12, R14, Limits, T03, T14; 028 R10, R14 |

Round 23: 14 findings (J23-A1–J23-A4, J23-B1, J23-B2, J23-C1–J23-C5, J23-D1–J23-D3), three Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J139 | On a full disk, entries a thief overtook stayed in the `outbox` and left once his blob expired, reading `Delivered` (J23-B1) | Medium | The held own-key values include the overtaken counter; `outbox` never hands those entries out, and the next successful commit removes them as not delivered (`HeldOwnKey`, `held_own_key`, `hold_own_key`; specs 021 R19, Interface, T19; 027 R14) |
| J140 | Slice 021 (d) at about 700 lines, 028 (c1) near 500 (J23-C4, J23-C5) | Medium | Split into (d1)/(d2) and (c1a)/(c1b) |
| J141 | No clock for calls without `now` (a regression of J131) (J23-C1, J23-D1) | Medium | Times measured with the `now` of the last call that carried one (spec 027 R14, T14) |
| J142 | Small ones: a memory-only retirement copy acknowledged against the stored `sent_at`; `own_pk` for the key comparison; `storage_full` passed to `set_write_failed`; any `Ok` direct writer skipping the ten-minute wait; empty cleaned names; missing tests and the Limits row (J23-A1–A4, J23-B2, J23-C2, J23-C3, J23-D2, J23-D3) | Low | Memory copies get a fresh `client_ref`; specs 021 R20, R22, Interface, Security, T20; 022 R6, T06; 025 R4, T04; 027 R7, R12, Limits, slices, T07, T14; 028 R10, Interface, T10, T16 |

Round 24: 15 findings (J24-A1–J24-A4, J24-B1–J24-B3, J24-C1–J24-C5, J24-D1, J24-D2), five Medium, overlapping. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J143 | A memory-only retirement copy, minted with a fresh `client_ref` on every call, was published every tick while the disk failed (J24-A1, J24-B3, J24-C1, J24-D1) | Medium | One memory copy per minute, kept and handed out again, counted in flight, `acked` as `Ignored` with its `sent_at`, and held as the current copy (specs 021 R22; 025 R4, T04; 028 R12) |
| J144 | A regeneration with own-key values held in memory gave the new key the old key's `read_only` and exhausted counter; the old key's overtaken entries had no hold (J24-B1, J24-B2) | Medium | The regeneration commit first applies the held values and removal to the old key; `HeldOwnKey` gains `old_key_overtaken_through` (specs 025 R1, T01; 021 R19, Interface, T19) |
| J145 | Small ones: outcomes of the held removal not drained; an `ack` of a covered entry; empty and whitespace-only names, U+2028/U+2029; the `local_name` Limits row; a stale comment (J24-A2–A4, J24-C2–C5, J24-D2) | Low | Specs 021 R19, Interface, T19; 022 R5, R6, T06; 027 R14, Limits, T07; 028 R11 |

Round 25: 12 findings (J25-A1–J25-A4, J25-B1, J25-C1–J25-C3, J25-D1, J25-D2, and J25-B2 as information), four Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J146 | A removal held after `LogFull` made every later state-only commit, regeneration included, fail with `LogFull` (J25-C1) | Medium | A commit carrying a held removal that fails with `LogFull` is retried once without it; regeneration moves the held counter to `old_key_overtaken_through` (specs 021 R19, T19; 025 R1, T01) |
| J147 | Entries held from `outbox` still blocked the retirement behind them (J25-D1) | Medium | They count as gone for 025 R4's ordering rule (specs 021 R19, T19; 025 R4, T01) |
| J148 | Slices 021 (d2) and 025 over 400 lines (J25-C2, J25-C3) | Medium | 021 (d2a)/(d2b); 025 gains slices (a)/(b) |
| J149 | Small ones: a memory copy's `ack` in 025 R5, `decrypt`'s old-key fallback untested, §7's invisible set, T05's members, an echo of a held entry, a downgraded config shown as corrupt (J25-A1–A4, J25-B1, J25-B2, J25-D2) | Low | Specs 021 R6, R13, R19, T06, T09, T13, T19; 022 T05, T06; 025 R5; `docs/spec.md` §7 |

Round 26: 10 findings (J26-A1–J26-A5, J26-C1–J26-C3, J26-D1, J26-D2); pass B clean. Two passes stopped at the spend limit and were run again. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J150 | A newer app's state, log or settings read as `Corrupt` by an older app and was offered for removal (J26-D1) | Medium | Key 0 of the state and settings records read first, `UnsupportedVersion` when not 1; any later schema change raises it (spec 020 R8, T08) |
| J151 | A suspended process or dead socket marked the channel synced on resume, hiding a truncation (J26-D2) | Medium | A call more than 5 000 ms after the previous one stops `synced` on that connection and asks for a reconnect; the half-open window documented (spec 028 R9, T09, Security) |
| J152 | Slices 021 (c) and 028 (b) far over 400 lines (J26-C1, J26-C2) | Medium | Split into (c1)/(c2) and (b1)/(b2) |
| J153 | Small ones: the old-key hold not covering `acked`, R3's exception list, the (d2a) guards, T06's Cc clause, test labels and `commits = 0`, a 021 clause needing spec 025 moved to 025 T04 (J26-A1–A5, J26-C3) | Low | Specs 021 R3, R19, slices, T06, T19; 022 T06; 025 T04 |

Round 27: 13 findings (J27-A1–J27-A4, J27-B1, J27-B2, J27-C1–J27-C3, J27-D1, J27-D2 and two already fixed during the pass), one High. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J154 | The 5 000 ms rule of round 26 measured from before a reconnect, so a slow handshake reconnected for ever; an `on_frame` after a suspension dodged it (J27-A1, J27-B2, J27-C1, J27-C2) | High | Measured from the latest `on_connect`, `on_tick` or `on_frame`, only with a subscribed channel, for frames too; `on_connect` resets it (specs 028 R5, R9, Limits, T09; 021 R20; 027 Limits) |
| J155 | `HeldOwnKey` had no flag, so an old-key-only hold raised a false alert over a reopen (J27-C3) | Medium | `own_key_used_elsewhere` field; `hold_own_key` sets the flag only when held (specs 021 Interface, R19, T19; 025 T01) |
| J156 | A forged `store_version` byte made a channel unremovable; a downgrade overwrote a newer app's settings (J27-B1, J27-A3) | Low | `remove_broken` and `replace_broken` offered for `UnsupportedVersion` behind a destructive confirmation; `settings_reason`, and no save over a newer `settings.bin` (spec 027 R1, R2, R3, R5, T02, T05) |
| J157 | Small ones: R3's exception for held values, several compactions in one tick, `leave` of a poisoned marked channel (J27-A4, J27-D1, J27-D2) | Low | Specs 021 R3, T03; 027 R8, R12, T12, T14 |

Round 28: 14 findings (J28-A1–J28-A6, J28-B1, J28-B2, J28-C1, J28-C2, J28-D1–J28-D4), one Medium, overlapping. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J158 | A newer (or forged) `settings.bin` could never be written over again: every unlock gated, no proxy (J28-B1, J28-D1) | Medium | A version byte forged over a version-1 box reads as `Corrupt`; `acknowledge_settings(replace_newer)` overwrites a genuine newer file behind a destructive confirmation (specs 020 R7, T07; 027 R2, Interface, T02) |
| J159 | The settings `UnsupportedVersion` path left the flag, the re-read after `Io` and the memory-only setters undefined (J28-A2, J28-A3, J28-C1, J28-C2, J28-D2) | Low | `settings_reset` cleared, `settings_reason` kept for the unlock; the re-read follows the same branch; tests (spec 027 R2, T01, T02) |
| J160 | Small ones: 021 R6's reason, `ok` after the gap on the same connection, the handshake not covered by the 5 000 ms rule, R8's test label, probes and retries outside the per-tick budget, the clearing time after a clock set back (J28-A1, J28-A4–A6, J28-B2, J28-D3, J28-D4) | Low | Specs 021 R6; 027 R12, R14, Limits, T08, T12, T14; 028 R9, Limits, Security, T09 |

Round 29: 10 findings (J29-A1–J29-A5, J29-B1, J29-C1, J29-C2, J29-D1, J29-D2), one Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J161 | The clamps added for row placement had undone ADR 0034's two-sided `ack` check: a sender clock a day off showed every message `Delivered` while every receiver discarded it (J29-D1) | Medium | `Delivered` needs the server's unclamped `received_at` within the margin of `sent_at`; the clamped time only places the row (spec 021 R13, R17, T17) |
| J162 | The forged-header exception was undefined for `messages.log` and could not be told apart through the Interface; R8 still let `store_version` rise alone (J29-A1, J29-A2, J29-B1, J29-C1, J29-C2, J29-D2) | Low | Exception defined by `open` returning `Ok`, for `state.bin` and `settings.bin` only; a log byte other than 1 next to a version-1 state is `Corrupt`; schema changes raise key 0 (spec 020 R7, R8, code split, T07) |
| J163 | Small ones: `replace_newer` outside `UnsupportedVersion`, the failure rule and T21's settings writers, T03 against the per-tick budget (J29-A3–A5) | Low | Spec 027 R2, T02, T03, T21 |

Round 30: 11 findings (J30-A1–J30-A5, J30-C1, J30-C2, J30-D1–J30-D4), one Medium; pass B clean. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J164 | A device clock off by more than the TTL showed a dead channel and failing messages with no reason; the §6 clock warning had no implementation (J30-D1) | Medium | `ChannelStatus::clock_off` from the server's `received_at` of the last `ack` or push (spec 021 R25, Interface, T25) |
| J165 | Small ones: T13/T17 inputs and the echo path of J161, 020's code split and T07 against R7, T05's early `ack`, no `hello` timeout after `on_connect` or for the probe, the server's frame types under `proto_version` 1, an unreadable `Io` entry without `channel_id` never removable (J30-A1–A5, J30-C1, J30-C2, J30-D2–D4) | Low | Specs 020 code split, T07; 021 T13, T17; 025 T05; 027 R3, R12, T03; 028 R4, R7, T07 |

Round 31: 10 findings (J31-A1–J31-A6, J31-B1, J31-C1, J31-D1, J31-D2), one Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J166 | `clock_off` turned on falsely after nearly every reconnect, from backlog pushes that are legitimately old, teaching users to ignore it or to change a correct clock (J31-B1, J31-C1) | Medium | Set and cleared by `acked`; only set by a push dated ahead of `now`; advice from an untrusted server, the client never suggesting a time (spec 021 R1, R25, T25, Security) |
| J168 | A marked channel with no connection never reported its stale entries, so failed rows vanished still `Pending` (J31-D2; J31-D1 as J166) | Low | `expire_outbox` runs on marked channels too and, like `outbox`, reports stale entries from memory when its commit fails (specs 021 R23, T23; 027 R12, R14, T14; 028 R14, T14) |
| J167 | Small ones: `clock_off` beside, not instead of, §6's per-message warning; R4's "table above"; the `hello` wait row; the probe timeout's Limits row (J31-A1–A6) | Low | Specs 021 R25, Public API changes; 027 Limits; 028 R4, Limits |

Round 32: 10 findings (J32-A1, J32-A2, J32-B1–J32-B3, J32-C1, J32-D1–J32-D4), four Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J169 | `expire_outbox` could not return its stale entries and its error together (J32-A1, J32-C1) | Medium | It returns an `OutboxStep` with `store_error`; callers treat that error as R14 does (specs 021 R23, Interface; 027 R12; 028 R14) |
| J170 | `clock_off` missed short channels and read-only devices, stuck after a fixed clock, rose falsely on a suspended `ack` or held push (J32-B1–B3, J32-D1) | Medium | Fed only by `clock_sample(received_at, now, live)` from the session: live for an `ack` within 5 000 ms of its publish and a push after `ok`, not for a frame past R9's gap; a short-TTL threshold for acks (specs 021 R25, Interface, T25; 028 R11, T11) |
| J171 | Without a proxy a `.onion` channel got a direct route, asking the ISP's resolver for the hidden service (J32-D2) | Medium | Such a channel is in no run and shows `needs_proxy`; `probe_plan` refuses it (spec 027 R10, R12, `ChannelInfo`, T10, T12) |
| J172 | Small ones: the client rule for `clock_off` had no home; a reopen lost the gaps, ignored keys and `clock_off`; the truncation banner could not be repainted (J32-A2, J32-D3, J32-D4) | Low | Specs 021 R1, R25, Interface, T01, T24, Security; 027 R14, T14 |

Round 33: 19 findings (J33-A1–J33-A8, J33-B1–J33-B3, J33-C1–J33-C4, J33-D1–J33-D4), one High and four Medium. Grouped, with the changes applied:

| # | Finding | Severity | Change |
| --- | --- | --- | --- |
| J173 | `carry_session(&Channel)` needed the old channel after it had to be dropped (J33-C1) | High | `session_carry()` read before the drop, `carry_session(SessionCarry)` after (specs 021 R1, Interface, T01; 027 R14; 026 R6) |
| J174 | `clock_off` still rose falsely on buffered and held pushes, and a live push cleared a short-channel alarm (J33-A1, J33-B1, J33-B2, J33-A2, J33-A3) | Medium | Only an `ack` within 5 000 ms of its publish, on a connection whose gap has not tripped, is a live sample; pushes only set it when dated ahead, and a newer in-margin one clears it; the read-only fast clock documented (specs 021 R25, T25, Security; 028 R11, R13, T11, T13) |
| J175 | A clock ahead by more than the TTL advanced the cursor past pushes the server still held (J33-D1) | Medium | Such a push leaves the cursor (spec 021 R20, T20, Security; 028 Security) |
| J176 | `truncated_before` needed a `now` `status()` does not take (J33-C2) | Medium | Judged against the `now` of R1's latest timed call (specs 021 R1, R25, T24) |
| J177 | Small ones: `.onion.` with a trailing dot, the stray comment, `needs_proxy` fields and re-read, `probe_plan` precedence while reset, a future `truncated_at`, own rows after a corrected clock, test labels (J33-A4–A8, J33-B3, J33-C3, J33-C4, J33-D2–D4) | Low | Specs 021 R24, T24, Security; 027 R2, R7, R10, R12, R14, `ChannelInfo`, T02, T10 |

Audit J was stopped after round 33 with the human reviewer's agreement: rounds 22–33 kept finding 10–20 findings each, nearly all Low edge cases of the full-disk, clock and version paths, and pass B (adversarial) had come back clean in rounds 26 and 30. What remains is left to implementation and its tests.

**Decisions** (taken with the human reviewer on 2026-09-25, every recommendation accepted): ADR 0037 accepted (one `Device` handle); 020-R10 (`state.bin` rewritten on every commit); 021-R9 (an AGENTS 22 exception for public identifiers used as map keys and for ordering, applied to AGENTS when 021 is accepted) and the display-expiry clause for §4 step 2; 022-R7 (no "remove label" in v1) and the documented residual for look-alike names; 023-R1 (one's own delivered plaintext kept up to one TTL longer, said in §1) and 023-R5 (purge thresholds, §8 reworded); 026-R2/R3 (muted unknowns never evicted) and 026-R6 (the ignored-keys count in memory); 028-R4 (backlog before `ok`) and 028-R16 (`error` names the channel and the entry). The reviewer also accepted the design choices made during the audit: seen records (J90), the `write_failed` probe (J131), `clock_off` (J164–J174), no `.onion` without a proxy (J171) and version handling (J150, J158).

Not changed on purpose: the whole log of an open channel stays in memory (J-C12), documented in spec 021 with a lazy list as a v1.x option; the unread marker is out of v1 (J-D19); the muted-unknown exception, the backlog before `ok` and the `error` keys are open questions of specs 026 and 028 for the human reviewer; ADR 0037 is `proposed` until the human reviewer decides it.

## Phase 2 drafts

**2026-09-25 — Decisions taken while drafting the phase 2 specs 020–028.** Not an audit: writing specs 020-store-files and 021-channel-session raised five questions, which the human reviewer decided with the recommended option before specs 022–028 were written. The specs themselves stay `draft` until their own review.

| # | Question | Decision | Change |
| --- | --- | --- | --- |
| P1 | ADR 0021 had no log header, nothing binding a log entry to its place, and channel directories named by the plain `channel_id` | Log header with a generation; `generation` and `offset` inside each record; directory named by a keyed hash under `K_db` | ADR 0035; spec 020 R4, R7, R18 |
| P2 | `encrypt` returned the blob while `outbox()` also publishes it (D10 of audit I) | `encrypt` returns only the `ClientRef`; every blob leaves through `outbox()` | §9; spec 021 R6 |
| P3 | §8 and spec 100 assumed a crate that logs | `core` emits no log in v1; the log test runs over the server | §8; spec 021 R25; spec 100 depends on 035 |
| P4 | The name comparison of §7 needs Unicode tables `core` did not have | `unicode-normalization` and `unicode-security` in `core`; casefold is the lowercase mapping | ADR 0036; §7, §9; spec 022 R4 |
| P5 | The frame keys were spec 030's (phase 3), but the client session of spec 028 (phase 2) needs them first | Spec 028 fixes the frame keys; spec 030 reuses its encoders on the server | §6; spec 028 R1–R3 |

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
