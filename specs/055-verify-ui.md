# 055 — Trust UX and verification screens

Status: draft
Phase: 5
Related ADRs: 0006, 0007, 0016, 0019, 0025, 0028, 0029, 0034, 0036, 0037
Depends on: 014-fingerprint, 021-channel-session, 022-peers-tofu, 023-ttl-purge, 024-key-retired, 025-identity-regen, 026-peer-limits, 027-core-api, 040-uniffi, 041-desktop-bridge, 054-qr-invite
Blocks: 050-desktop-mvp, 051-android-mvp, 052-ios-mvp
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The core decides every trust fact: whether a key is unknown, labelled, verified, muted or retired, whether its name collides with another, whether its short identifier matches another's, whether someone wrote with the user's own key (specs 022-peers-tofu, 024-key-retired, 025-identity-regen, 026-peer-limits, reached through `Device`, spec 027-core-api). `docs/spec.md` §7 fixes how the user sees those facts and what the user can do about them. This spec turns §7 into requirements that the three clients (specs 050-desktop-mvp, 051-android-mvp and 052-ios-mvp) render identically. It also defines the verification screen on each platform: the user's own verification QR and 12 words, comparing the 12 words with a peer, and, on the phones, scanning a peer's verification QR. §12 names impersonation under trust-on-first-use as a main risk; this spec is where the user meets it.

Nothing here decides trust. Each rule is a pure mapping from the records the core returns (`Peer`, `Message`, `Stranger`, `ChannelStatus`, `Fingerprint`) to what is drawn, or a call of one `Device` method in response to one user action (architecture skill §7: "views decide presentation, never trust").

**In plain words.** Everyone in a channel is a key. A key you have never named shows its suggested name in grey, in quotes, with four words that tell it apart. You can give it a name, and you can verify it: with the person in front of you, compare 12 words on both screens, or scan the QR on their phone. A verified name gets an icon that no name can imitate. If a new key uses the name of someone you know, the app warns you, and helps you retire the old key once you have checked. If someone writes with your own key, a banner tells you and offers to make a new one. These screens look and behave the same on the desktop, Android and iOS.

## Requirements

**One presentation, three platforms**

- R1 Each client MUST derive what it draws for a peer, a message sender and a channel card from the core's records alone, through one pure function per platform: `presentPeer(peer, context)`, `presentSender(message, context)` and `presentChannel(status, info, context)`. `context` is a `TrustContext` that the caller fills from the core before calling: the channel's `peers`, the user's `own_fingerprint` and `own_display_name`, the `fingerprint` of every peer whose `short_collides` is true, and the locale and date formatter used for `retired_at`. Each function returns a value of the Interface's presentation model and reads nothing else (no store, no network, no clock). The three platforms' functions MUST give the same model for every row of the shared fixture `clients/fixtures/trust_presentation.json`, which holds each row's records, context and expected model. Android and the desktop load it in place; on iOS the Xcode test target references the file in place (a folder reference), since the app is an Xcode project and not a SwiftPM package.
- R2 Every name drawn MUST come from the record as the core cleaned it (spec 022-peers-tofu R6: Cc and the `INVISIBLE` set removed, an empty name as `None`) and MUST be rendered as text, never as markup. A `None` name MUST be drawn as the platform's placeholder string for "no name", never as an empty space. A name MUST be clipped to one line and truncated first: the verified icon, the marks, the quotation marks and the short identifier are drawn outside the name's text run, in fixed positions, and are never truncated or overlaid, so that no name (`Bob ✅`, `Bob (verified)`, a stack of combining marks) can imitate the icon or push a mark off screen.
- R3 Every string of this spec MUST live in the platform's resource files, with English as the source and the UI languages of `docs/spec.md` §12. Where §7 fixes a text, the English source MUST be that text word for word: the texts in quotes in R4–R20 are those sources. Dates (`retired_at`) MUST be formatted by the platform's locale-aware short date formatter, day and month.

**Peer states** (`docs/spec.md` §7 "Presentation rules")

- R4 Unknown (no label, not verified, not retired): the suggested name MUST be drawn in the secondary colour, between the locale's quotation marks, with no avatar, followed by the short identifier (the 4 words of `Peer::short` or `Stranger::short`) and the "unknown key" mark. Every message from an unknown sender carries the same mark. An unknown MUST NEVER be drawn with another peer's label or with the user's own name.
- R5 Labelled: the label MUST be drawn in the primary colour. When `Peer::label_collides` is true, the short identifier MUST be drawn next to it.
- R6 Verified: the label and the "verified" icon, whose accessibility label is "Verified". The icon belongs to the `pk`: a message from another key with the same name never carries it.
- R7 Retired (`retired_at` set), in the secondary colour: "{label} (key retired on {date})" for a peer with a label, and "“{suggested_name}” (key retired on {date})" for one without (spec 024-key-retired R4 retires any record, an unknown one included). A retired peer is never drawn as unknown. Muted: the peer's normal state plus the "muted" mark; the messages of a muted peer are shown collapsed behind "Muted: show".
- R8 Wherever a short identifier is drawn, it MUST carry the caption "identifier, not verification", and no action MUST verify a peer from it: the short identifier is never an input (spec 014-fingerprint R6).

**Warnings**

- R9 For a peer or a stranger whose `claims_name_of` is set, the client MUST show in the channel, next to that sender's messages and on its card: "Someone claims to be {label} with a new key. Verify them before trusting them", where `{label}` is the label of the peer that `claims_name_of` names. For `claims_own_name`, it MUST show: "Someone uses your name with another key. If it is one of your devices, verify it on your other device, side by side; if it is your old device, mark that key as retired". `claims_own_name` compares with `own_display_name`, which the core sets at the user's first send in the channel (spec 022-peers-tofu R13): on a fresh install the warning appears only once the user has written there, and R16 says so.
- R10 For a peer whose `Peer::short_collides` is true, its card MUST show the 12 words of that peer and of each other peer with the same short identifier (or of the user's own key), from the fingerprints in `context` (R1), under "Identifier identical to another member: possible impersonation. Verify by QR", §7's text word for word, and MUST offer "Compare 12 words" (R18) on that card on every platform, since the desktop cannot scan (R20).
- R11 While `ChannelStatus::own_key_used_elsewhere` is true, the channel MUST show a fixed banner that cannot be dismissed: "Someone has written with your key in this channel", with the action "Regenerate my key" (R14). A message whose sender is `Sender::OwnKeyElsewhere` MUST be drawn with the user's own name, the "not sent from this device" mark and no delivery state. While `read_only` is set, the composer MUST be disabled with the text "Your key was retired from another device. Regenerate your key to write again".
- R12 The channel card MUST show "{n} new keys ignored" while `ignored_keys` is above 0, and "Too many unknown keys: new ones are ignored until they are forgotten or named" while `unknown_limit_reached`. A `label`, `verify` or `verify_scanned` that returns `PeerLimit` MUST show "This channel already has 500 named members. Forget some to name or verify more", and while `labelled_limit_reached` is true, the actions that would name or verify an unknown MUST show that text instead of acting. "Mark this key as retired", "Mute" and "Forget" stay offered at the limit, since retiring is never refused (`docs/spec.md` §7) and needs no name (R15).
- R13 While `ChannelStatus::clock_off` is true, the channel MUST show "this device's time differs from the server's; turn on automatic time" (spec 027-core-api R14), never a time or an offset.

**Actions on keys**

- R14 "Regenerate my key", on the channel card and in the banner of R11, MUST first show the prior warning "you will appear as unknown again; members who do not open the channel within its message lifetime will not receive the retirement, so ask them to mark your old key as retired", and call `regenerate_identity` only after the user confirms. `RetirementPending` MUST show "Your previous key is still being retired. Try again once it is delivered". While `retirement_pending` is true, the channel card MUST show "retirement pending". The card MUST list `own_old_keys` with their dates, under "Your earlier keys in this channel".
- R15 Each peer card MUST offer "Name", "Verify", "Mute" or "Unmute", "Mark this key as retired" (for every peer that is not retired, an unknown one included) and "Forget". Their rules:
  - "Mark this key as retired" MUST explain "Messages from this key will be rejected from now on. Use this when the person lost the device or regenerated their key. Only if they told you in person or on a call. A request in this chat from a new key may come from an impostor. This cannot be undone." and call `retire` only after the user confirms.
  - "Forget" MUST explain "This removes the key and its name from this device. If it writes again it will appear as unknown" and call `forget` only after the user confirms.
  - A label typed by the user is checked by the client for shape only (not empty, at most 64 bytes in UTF-8) before any call; the core applies the rest (spec 022-peers-tofu R7).
  - The errors map as follows: `BadPayload` for a label → "Names cannot be empty or longer than 64 bytes"; `UnknownPeer` → "This key is no longer in the channel", followed by a re-read of `peers`; `LabelInUse` → "Another member already has this name. Verify this key to give it the same name, or choose another", with exactly the actions "Verify" (listed first and the default) and "Choose another name". Moving a name to a key that is not verified is never offered here: the retirement of the old key comes only after the new one is verified (R18, R19), since a request to be named is exactly what an impostor with a new key asks for.
- R16 The text "the others will keep seeing your old key as valid; ask them to mark it as retired" MUST be shown under the regenerate action, after "If you lost the device that had your old key:", together with "The warning about your own name appears once you have written in this channel". A user whose old device is lost marks that key retired like any peer's: an unknown peer with `claims_own_name` offers "Mark this key as retired" on its card (R15), which calls `retire` on its record. A stranger (a sender with no record, spec 023-ttl-purge R3) offers no action and shows "Wait until this key writes again, or ask the others to mark it retired".

**The verification screen**

- R17 Each channel MUST have a verification screen that shows, for the user's own key, the verification QR and the 12 words from `own_fingerprint`, under "Show this to the person you are verifying, face to face. Verification is mutual: each of you checks the other". The QR MUST be drawn by the renderer of spec 054-qr-invite from `Fingerprint::qr`. On the desktop, that is the SVG of the `qr` scheme of spec 041-desktop-bridge, through the command `export_verify_qr`: the verification QR is public, but one renderer keeps one audited path and no QR encoder enters the web view.
- R18 Verifying a peer by the 12 words, on every platform: the peer's card MUST offer "Compare 12 words". It MUST first ask "Is this person in front of you, or on a voice call you placed yourself?", with "Yes, go on" and "Cancel", and only after "Yes, go on" show the peer's 12 words from `fingerprint(pk)`, numbered 1 to 12, next to the text "Ask them to read their 12 words from their screen. Every word must match, in order. Only with the person in front of you, or on a voice call you placed yourself; never from a message or a picture", and exactly two actions: "All 12 match" and "They differ". There MUST be no partial match: nothing is typed, and no subset of the words is ever enough (spec 014-fingerprint, "partial-match rule"). "All 12 match" calls `verify(pk, label)`, asking first for a label when the peer has none; "They differ" changes nothing and shows "Do not trust this key. Someone may be impersonating this person". When the peer had `claims_name_of` set before the verification, the verified card MUST then offer, with R15's retire confirmation, "Mark {label}'s old key as retired and give this key the name", which calls `retire(old)` on the peer that `claims_name_of` names and then `label(peer, {label})`; with no `claims_name_of` there is no offer, since finding a colliding peer by its name would be logic in the UI.
- R19 Verifying by QR, on Android and iOS only: the verification screen MUST offer "Scan their QR", which first asks "Is their phone in front of you?", with "Yes, go on" and "Cancel" and no call option, since a verification QR seen on a call or in a picture is the impostor's route, and only after "Yes, go on" opens the scanner of spec 054-qr-invite with `purpose = Verify` and the line "Scan only their phone's screen, never a picture sent to you." The client passes the scanner an accept predicate that checks the shape alone (the text starts with `verify:v1:` and is exactly 74 bytes; not a trust decision): a payload it refuses shows "This is not a verification QR", is zeroed at once, and the scanner stays open. Then the client asks for a label typed by the user, with "If this key already has a name, it keeps it", checks its shape as R15 does, and calls `verify_scanned(channel, bytes, label)`. It is the only way to verify a key before its first message (pre-verification, `docs/spec.md` §7), and it MUST say so: "You can verify someone's new device before they write, with the device in front of you". The errors map as follows: `WrongChannel` → "This QR is for another channel"; `OwnKey` → "This is your own key"; a `BadPayload` after the shape check → R15's text for a label; the errors of R12 and R15 as there. On success the verified peer's card opens, with the label the peer actually carries after a re-read of `peers`, and with R18's offer when that peer had `claims_name_of`. The accepted payload MUST be zeroed on every exit of the flow: after the `verify_scanned` call, and at once on a cancel at the label step, on going to the background and on lock.
- R20 The desktop MUST NOT offer a way to enter a peer's verification QR or its text: it has no camera (`docs/audit-log.md`, "Phase 5 drafts", Q3), and a verification text pasted from elsewhere would travel over a channel that is not the in-person meeting the check exists for. A desktop verifies by the 12 words (R18), and a phone verifies the desktop by scanning the desktop's QR (R17). In the pull request that marks this spec `accepted`, spec 041-desktop-bridge R4 and T04 MUST drop the `verify_scanned` command, so that the desktop has none.

**Tests**

- R21 Each platform MUST test the functions of R1 against every row of `clients/fixtures/trust_presentation.json`, and MUST have one UI test of the flow "verify a peer" (architecture skill §7): open a peer, answer the in-person question, compare 12 words, confirm, see the verified icon; on the phones, the same by a scanned QR with a fake scanner.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| A label typed by the user | 1..=64 bytes in UTF-8, checked by the client for shape; the rest by the core (spec 022-peers-tofu R7) | the text of R15, no call; `BadPayload` from the core, the same text |
| Words compared | exactly the 12 of `Fingerprint::words` | no partial match (R18) |
| Named members per channel | ≤ 500 (spec 026-peer-limits) | `PeerLimit`, the text of R12 |
| Scanned verification QR | starts with `verify:v1:`, exactly 74 bytes (spec 014-fingerprint) | "This is not a verification QR", the scanner stays open |
| A name drawn | one line | truncated; icon and marks kept (R2) |

## Interface

```
clients/fixtures/trust_presentation.json                                R1: records and context → the presentation model
clients/android/app/src/main/kotlin/org/privatechat/ui/trust/          Presentation.kt (R1), PeerCard.kt, VerifyScreen.kt
clients/android/app/src/main/kotlin/org/privatechat/viewmodel/         VerifyViewModel.kt, PeerViewModel.kt
clients/ios/Privatechat/Views/Trust/                                    Presentation.swift (R1), PeerCard.swift, VerifyScreen.swift
clients/ios/Privatechat/ViewModels/                                     VerifyModel.swift, PeerModel.swift
clients/desktop/src/lib/ui/trust/                                       present.ts (R1), PeerCard.svelte, VerifyScreen.svelte
clients/desktop/src/lib/state/                                          verify.svelte.ts
```

The presentation functions are a pure mapping and belong to the UI layer; they call no `Core` method. The presentation model, the same on every platform (field names in each language's case):

```
TrustContext { peers: [Peer], own: Fingerprint, ownDisplayName: String | none, colliding: {PeerId → Fingerprint}, dates: locale formatter }
PeerView    { name: Text | Placeholder, quoted: bool, secondary: bool, verifiedIcon: bool,
              short: [4 words] | none, shortCaption: bool, marks: {unknown, muted, retired(date), notThisDevice},
              warnings: [ClaimsNameOf(label) | ClaimsOwnName | ShortCollides([12 words] per key)],
              actions: [Name, Verify, Mute | Unmute, Retire, Forget] }
SenderView  PeerView of the sender, or Own, or OwnKeyElsewhere, or Stranger { short, warnings, hint: WaitOrAskOthers }
ChannelView { banners: [OwnKeyElsewhere, ReadOnly, ClockOff], card: [IgnoredKeys(n), UnknownLimit, LabelledLimit, RetirementPending] }
```

Screen state and intents (architecture skill §7):

```
VerifyState  = Loading | Ready { own: Fingerprint, peer: Option<PeerView> } | InPersonCheck { then } | PhoneInFrontCheck | Comparing { peer, words }
             | Scanning | NeedLabel { then } | OfferRetireOldAndName { old, label } | Failed(kind)
VerifyIntent = CompareWords(peer) | InPersonYes | PhoneInFrontYes | WordsMatch | WordsDiffer | ScanQr | Scanned(bytes) | LabelTyped(label) | RetireOldAndName | Cancel
PeerIntent   = Name(label) | Verify | Mute(bool) | Retire | Forget | Regenerate
```

`Scanned` carries the bytes the scanner of spec 054-qr-invite returns once its accept predicate (R19) has passed them, handed to `verify_scanned` and not kept. A payload the predicate refuses is zeroed at once; an accepted one is zeroed after the call, or at once on a cancel, on going to the background or on lock (R19): an invitation QR scanned here by mistake holds `K_ch`.

Test names: each T below is `s055_tTT_rRR_<name>`, in snake_case in Kotlin and in camelCase after the `sNNN_tTT_rRR_` prefix in Swift and in the desktop's Vitest (for instance `s055_t01_r01_presentationFixture`), so that `scripts/check_requirements.sh` finds each on every platform.

**PR slices** (AGENTS 14), per platform: (a) the fixture and the functions of R1 with their tests (R1–R13); (b) the peer card and its actions (R14–R16); (c) the verification screen and the UI test (R17–R21).

## Security

- The client never decides trust (R1). A bug in a presentation function can draw a wrong colour; it cannot make an unverified key verified, since the verified icon comes from `Peer::verified` alone and no action verifies without `verify` or `verify_scanned`.
- No partial match of the words (R18) and no verification from the short identifier (R8): 44 bits can be matched by an attacker who grinds keys; 132 bits cannot (spec 014-fingerprint).
- An impostor who already holds the config can post "my new phone, please verify: word1 … word12" or a picture of their verification QR. The in-person questions and the texts of R18 and R19 make that route explicit and wrong, the QR path offers no call option, and a name moves to a new key only after it is verified (R15, R18); the app cannot tell a voice call from a message, so a user who ignores them can still verify an impostor, a documented residual (`docs/spec.md` §12, "TOFU confusion").
- The retire confirmation (R15) warns that a request to retire a key, arriving in the chat from a new key, may be an impostor's, since retiring cannot be undone and silences the genuine key for good.
- The desktop takes no verification text (R20), so every verification is an in-person comparison or scan, which is what the trust-on-first-use model rests on (`docs/spec.md` §7, §12).
- Names are rendered as text, on one line, with the icon and marks outside their run (R2), so a name can neither inject markup nor imitate the verified icon nor hide a mark; on the desktop that is also a defence of spec 041-desktop-bridge's web view.
- The warnings of R9–R11 cannot be dismissed while their cause stands, so an impostor cannot wait until the user clicks them away.
- An injected script on the desktop can call `verify` itself and forge the verified mark (spec 041-desktop-bridge, Security); this spec does not change that residual.

## Public API changes

None in the core. Spec 041-desktop-bridge serves `own_fingerprint`'s QR with `export_verify_qr(channel)` on its `qr` scheme (R17), and loses its `verify_scanned` command in the pull request that accepts this spec (R20).

## Test cases

- T01 (covers R1): `s055_t01_r01_presentation_fixture`: every row of the fixture, with its context, gives its expected model on each platform; the functions touch no `Core` method.
- T02 (covers R2): `s055_t02_r02_names_as_text`: a label of `<b>x</b>` is drawn as those six characters; a `None` suggested name is drawn as the placeholder; fixture rows for an unknown named `Bob ✅` and for a name of 64 bytes of stacked combining marks: the real icon's position stays empty, and the quotation marks, the short identifier and the unknown mark are all drawn untruncated.
- T03 (covers R3): `s055_t03_r03_strings`: every string key of this spec exists in the English resources with the text of R4–R20 and in each UI language; a `retired_at` is formatted with the locale's short date.
- T04 (covers R4): `s055_t04_r04_unknown`: fixture rows for an unknown with a suggested name, with none, and with a message: quoted, secondary, short identifier, the mark, no label.
- T05 (covers R5): `s055_t05_r05_labelled`: fixture rows for a labelled peer with and without `label_collides`.
- T06 (covers R6): `s055_t06_r06_verified`: fixture rows for a verified peer, and for another key with the same suggested name: only the verified one carries the icon.
- T07 (covers R7): `s055_t07_r07_retired_muted`: fixture rows for a retired labelled peer, a retired peer with no label (drawn with its quoted suggested name, not as unknown) and a muted unknown; UI check that a muted peer's messages are collapsed.
- T08 (covers R8): `s055_t08_r08_short_caption`: every drawn short identifier carries the caption, and no intent verifies from it.
- T09 (covers R9): `s055_t09_r09_claims`: fixture rows with `claims_name_of` and `claims_own_name` on a peer and on a stranger; the `claims_own_name` text says "side by side".
- T10 (covers R10): `s055_t10_r10_short_collision`: a peer with `short_collides` shows both 12-word lists from the context, §7's warning word for word and the "Compare 12 words" action on every platform; a collision with the user's own key shows `own`'s words.
- T11 (covers R11): `s055_t11_r11_own_key_banner`: `own_key_used_elsewhere` shows the banner, which has no dismiss action; an `OwnKeyElsewhere` row carries the mark and no delivery state; `read_only` disables the composer with its text.
- T12 (covers R12): `s055_t12_r12_limits`: fixture rows for `ignored_keys` 3, `unknown_limit_reached` and `labelled_limit_reached`; a `PeerLimit` from `label` shows the text; at the labelled limit an unknown still offers retire, mute and forget.
- T13 (covers R13): `s055_t13_r13_clock_off`: a fixture row with `clock_off` shows the text and no time.
- T14 (covers R14): `s055_t14_r14_regenerate`: the warning comes before the call, a cancel calls nothing; `RetirementPending` shows its text; `retirement_pending` shows on the card; `own_old_keys` are listed.
- T15 (covers R15): `s055_t15_r15_peer_actions`: each action calls its `Device` method only after its confirmation where R15 asks one, and the retire confirmation carries the impostor warning; an unknown offers retire; an empty label and one of 65 bytes show the text with no call; each error maps to its text; `UnknownPeer` re-reads `peers`; `LabelInUse` offers exactly "Verify", first and default, and "Choose another name", whatever `claims_name_of` holds.
- T16 (covers R16): `s055_t16_r16_own_old_key`: the regenerate action shows the lost-device text of §7 word for word; an unknown with `claims_own_name` offers "Mark this key as retired", which calls `retire`; a stranger with `claims_own_name` offers no action and shows the wait text.
- T17 (covers R17): `s055_t17_r17_own_verify_qr`: the screen shows the 12 words of `own_fingerprint` and a QR that decodes to its `qr` bytes (on the phones, through the renderer of spec 054-qr-invite; on the desktop, the `export_verify_qr` URL).
- T18 (covers R18): `s055_t18_r18_compare_words`: the in-person question comes first, and "Cancel" shows no words; two actions only; "All 12 match" on an unlabelled peer asks a label, then calls `verify`; "They differ" calls nothing and shows its text; after verifying a peer that had `claims_name_of`, the offer to retire the old key and give this key the name appears, and calls `retire(old)` then `label`; after verifying one without it, no offer appears.
- T19 (covers R19): `s055_t19_r19_scan_verify` on Android and iOS, with a fake scanner fed the 014 vectors: the question "Is their phone in front of you?" comes first, with no call option, and the scanner shows its line; `qr_wrong_prefix` and a text of 73 bytes are refused by the predicate → "This is not a verification QR", the scanner open, the payload zeros and no call; `qr_reference` → the label asked, `verify_scanned` with it, and the verified card with the label re-read from `peers`; `qr_other_channel` → the `WrongChannel` text; the user's own QR → the `OwnKey` text; a label the core refuses → R15's label text; the accepted payload is zeros after the call, and after a cancel at the label step, a move to the background and a lock.
- T20 (covers R20): `s055_t20_r20_desktop_no_verify_input`: the desktop verification screen has no scan action and no text input for a verification QR; once this spec is `accepted`, the command list of spec 041-desktop-bridge R4 has no `verify_scanned` (`check_s055_t20_r20_no_verify_scanned` in `scripts/doc_lint.py`).
- T21 (covers R21): `s055_t21_r21_verify_flow`: the UI test "verify a peer" on each platform: Compose UI test, XCTest UI test, `@testing-library/svelte`.

## Vectors

None of its own. T19 feeds the scanner fake with the verification QR vectors of spec 014-fingerprint (`qr_reference`, `qr_other_channel`, `qr_wrong_prefix`), and T17 checks the rendered QR against `own_fingerprint`. The fixture of R1 is UI data, not a protocol vector: it is not frozen by AGENTS 18 and changes with this spec.

## Acceptance criterion

On each platform, the tests of T01–T21 that apply to it green in CI (Android: `./gradlew test connectedCheck` on an emulator; iOS: `xcodebuild test`; desktop: `pnpm test`). Non-automatable: a second person verifies a peer on each pair of platforms (desktop and phone by words and by the phone scanning the desktop's QR; phone and phone by QR), reads every text of R4–R20 in English and one other UI language, and does a screen-reader pass over the verification screen and a peer card.

## Out of scope

- Rendering and scanning QR codes, the camera and its permission (spec 054-qr-invite).
- "Create new channel" and its help text of `docs/spec.md` §7 "Config compromise" (spec 054-qr-invite R3).
- The channel screen, the message list, the composer and the channel card's other actions, "Leave channel" among them (specs 050-desktop-mvp, 051-android-mvp, 052-ios-mvp).
- Whether a peer's state is right: specs 022–026.

## Open questions

None.

## History

- 2026-09-26 draft
- 2026-09-26 revised after audit M round 1 (`docs/audit-log.md`): an in-person question before words or scanner, and texts that rule out a message or a picture; the impostor warning on retire; icon and marks outside the name's run; retire on every record, an unlabelled retired peer defined, and the stranger's wait text; the retire-old-and-name action after `LabelInUse` or a verification; scan first with a shape check; the presentation context; the scanner's `Verify` purpose; no `verify_scanned` on the desktop; §7's lost-device text word for word; file layout and test names per platform
- 2026-09-26 revised after audit M round 2 (`docs/audit-log.md`): the 041 amendment made an acceptance-time one; a QR-only question with no call option and a scanner line; a name moves to a new key only after it is verified; the retire offer from `claims_name_of` alone; the scanner's accept predicate and zeroing on every exit; "Compare 12 words" on the short-collision card; the desktop files under `ui/` and `state/`; §7's regenerate warning word for word
