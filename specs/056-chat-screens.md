# 056 — Chat screens: the channel list, the channel, the composer, settings and help

Status: draft
Phase: 5
Related ADRs: 0008, 0014, 0019, 0020, 0027, 0034, 0037, 0041
Depends on: 021-channel-session, 023-ttl-purge, 027-core-api, 028-session-sans-io, 040-uniffi, 041-desktop-bridge, 042-connection-host, 053-device-security, 054-qr-invite, 055-verify-ui
Blocks: 050-desktop-mvp, 051-android-mvp, 052-ios-mvp
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Specs 053-device-security, 054-qr-invite and 055-verify-ui fix what the three clients share for the device, for invitations and for trust. What is left is the chat itself: the list of channels, a channel's messages and composer, the state of its connection, its card, the settings, the notices the core raises at unlock (spec 027-core-api R1–R3) and the help that other specs point to. These rules are the same on the desktop, Android and iOS, so they live here once, decided with the human reviewer on 2026-09-27 (`docs/audit-log.md`, "Phase 5 drafts", Q11). Specs 050-desktop-mvp, 051-android-mvp and 052-ios-mvp place these screens in each app and wire them to the platform.

As in spec 055-verify-ui, nothing here decides anything the core knows. Every rule is a pure mapping from the records the core returns (`ChannelInfo`, `DeviceStatus`, `Message`, `Gap`, `ChannelStatus`, `SettingsView`) and the host's events and connection states (spec 042-connection-host R5) to what is drawn, or one call in response to one user action (architecture skill §7).

**In plain words.** The first screen lists your channels, each with a dot for new messages and a word about its connection. A channel shows its messages in the order the server received them, each with who wrote it, when, and, for your own, whether it was sent. Messages disappear from the screen when their lifetime ends. If the server seems to have dropped messages, or older ones expired while you were away, the channel says so. You write at the bottom; the first time, the app asks what name the others will see. The channel's card holds its name, its invitation, its members and "Leave channel". Settings hold the default server, how long the app stays unlocked, and the Tor proxy. Help explains, in plain words, what the app protects and what it does not.

## Requirements

**One presentation, three platforms**

- R1 Each client MUST derive what it draws for a channel row, a message row, a gap, a connection state and a channel's banners from the core's records and the host's events alone, through one pure function per platform for each: `presentChannelRow`, `presentMessage`, `presentGap`, `presentConnection` and `presentBanners`, which read nothing else (no store, no network, no clock but the `now` they are given). `presentMessage` uses `presentSender` of spec 055-verify-ui R1 for the sender. The three platforms' functions MUST give the same model for every row of the shared fixture `clients/fixtures/chat_presentation.json`, loaded in place as spec 055-verify-ui R1 loads its own.
- R2 Every text a user or a peer wrote (a message body, a name, a label) MUST be rendered as plain text on one run, never as markup, and with no link detection: a URL in a body is not clickable, is not previewed and is not fetched, since a tap or a preview would reach the network outside the host and tell a server that the message was read. Names follow spec 055-verify-ui R2. A body keeps its line breaks and is wrapped, never truncated.
- R3 Every string of this spec MUST live in the platform's resource files, English source and the UI languages of `docs/spec.md` §12, with the texts in quotes in R4–R19 as the English source; where `docs/spec.md` fixes a text, word for word. Times are formatted by the platform's locale-aware formatter: the short time for today, the short date and time otherwise.

**At unlock**

- R4 After every successful unlock, before the channel list, the client MUST read `status()`, and while `settings_reset` is set it MUST show the settings notice, which no other screen replaces:
  - for `settings_reason` `None` or `Corrupt`: "The app settings were lost. Nothing connects until you check them: the proxy, if you used one, has to be set again.";
  - for `Io`: "The app settings could not be read. The app will try to read them again when you continue.";
  - for `UnsupportedVersion`: "These settings were written by a newer version of the app: update it, or replace these settings." (spec 027-core-api R2).
  Its actions are "Check settings", which opens Settings (R16), where setting the proxy clears the notice (spec 027-core-api R2), and "Continue", which calls `acknowledge_settings(false)`. For `UnsupportedVersion` it also offers "Replace settings", which calls `acknowledge_settings(true)` only behind a destructive confirmation with that same text; on the desktop that is the native confirmation of spec 041-desktop-bridge R16. After any of them returns `Ok`, the client re-reads `channels()` and `status()` (spec 027-core-api R14).
- R5 While `status().broken` is not empty, the channel list MUST show, above the channels, "Channels that cannot be read on this device", and one row per entry, named by `channel_name` or, without one, "An unreadable channel", with the text of its reason and one action:
  - `Corrupt`: "It could not be read: remove it and lose its local history." and "Remove";
  - `Io` with a `channel_id`: "This device's storage could not be read. The app tries again every ten minutes." and "Leave this channel";
  - `Io` without one: "It could not be read: remove it and lose its local history." and "Remove";
  - `UnsupportedVersion`: "Written by a newer version of the app: update it, or remove the channel and lose its local history." and "Remove".
  Every action calls `remove_broken(name)` only behind a destructive confirmation that repeats the text (spec 027-core-api R3); on the desktop, the native confirmation of spec 041-desktop-bridge R16. `UnknownChannel` re-reads `status()`; any other error shows "The channel could not be removed. Try again."

**The channel list**

- R6 The channel list MUST show one row per entry of `channels()`, in the order the core returns them, never re-sorted. A row shows the channel's `local_name`, or else its `suggested_name`, as R2 says; a "new messages" mark when a `Message` event from a peer arrived for that channel since it was last on screen, a mark the client keeps in memory only and drops at lock; the text of `presentConnection` (R10) when it has one; "Could not save" while `write_failed`. Its actions are "Create channel" and "Join a channel" (spec 054-qr-invite), "Settings", "Help" and "Lock now" (spec 053-device-security R10). With no channel and no broken entry, it shows "No channels yet. Create one, or join one with an invitation from someone in it."

**The channel screen**

- R7 The message list MUST show `messages(channel, now)` in the order the core returns them, which is the order of `received_at` (`docs/spec.md` §6), never re-sorted or filtered, keyed by `server_id`, or by `client_ref` for an own message the server has not acknowledged. A `HostEvent::Message` adds its row where the core's order puts it by a re-read (R11); a `Delivered` or `NotDelivered` updates the own row with that `client_ref`. Every 1 000 ms, while the screen is shown, a row whose `expires_at` is not after `now` MUST be removed, so that a message leaves the screen when it leaves the disk (spec 021-channel-session R26). The screen's header shows the channel's name and "Messages disappear after {lifetime}", with the lifetime from `ttl_seconds` in the largest whole unit of days, hours or minutes.
- R8 `presentMessage` MUST give, for each row:
  - the sender, from `presentSender`, and for `Sender::Own` the user's own name from `own_display_name`, or "You" without one;
  - the time of `received_at`, and, when `sent_at` is set and differs from `received_at` by more than 300 000 ms, the mark "Sent at {time} by the sender's clock" (`docs/spec.md` §6);
  - for `MessageContent::Text`, the body as R2 says; for `KeyRetired`, "{sender} retired this key."; for `Unreadable`, "A message from {sender} could not be read.";
  - for an own row, by `delivery`: `Pending` "Waiting to send", `Delivered` "Sent", `NotDelivered` "Not sent: it expired before reaching the server." with the action "Send again", which sends the same body as a new message and leaves this row as it is. "Sent" means the server accepted it, never that anyone read it;
  - the "Copy" action for a text row, through the clipboard of spec 053-device-security R14; the text is not selectable.
  The muted, `OwnKeyElsewhere` and stranger rules of spec 055-verify-ui R7, R11 and R16 apply.
- R9 `presentGap` MUST give, for each entry of `gaps(channel)`, one line in the channel above the list: "{n} messages from {sender} may be missing: the server may have deleted or delayed them.", with `n` the gap's `missing` and the sender from `presentSender` of the `Peer` it names; and for an `anomalous` gap, the text of `docs/spec.md` §4 instead, "anomalous counter jump: this key may be compromised", with the sender. `spans_truncation` changes nothing drawn. While `ChannelStatus::truncated_before` is set, the channel MUST show "There may be expired messages before {date}" (`docs/spec.md` §6), with the date and time of that value.
- R10 `presentConnection` MUST map the channel's state to at most one line, from the last `connection_state` the host emitted for a plan that holds the channel, and from `ChannelInfo::needs_proxy`:
  - `needs_proxy`: "Onion servers need a SOCKS5 proxy running on this device." (spec 027-core-api R10), followed by "Use 127.0.0.1, not localhost." when the proxy set is a host name;
  - `Connecting`, or no state received since unlock: "Connecting…";
  - `Connected`: nothing;
  - `Retrying`: "Offline. Trying again…";
  - `ServerFull`: "The server is busy. Messages will be sent when it has room.";
  - `UnsupportedServer`: "This server runs a version of the protocol this app does not speak.";
  - `ProxyRefused`: "The proxy refused the connection. Check the proxy in Settings.";
  - `Failed`: "This channel stopped working on this device. Leave it and join again with a new invitation." (spec 042-connection-host R7).
  The states are held in memory, per channel, and dropped at lock.
- R11 `presentBanners` MUST give the channel's banners, in this order, besides those of spec 055-verify-ui R11 and R13:
  - after `SubscribeRefused`, until the next `Subscribed` of that channel or the next unlock: "The server refused this channel. Ask for a new invitation.";
  - after `ChannelFull`, until the next `Delivered` of that channel or the next unlock: "Channel full: probably flooded. Create a new one" (`docs/spec.md` §6), with the "Create new channel" action of spec 054-qr-invite R3;
  - while `ChannelInfo::write_failed`: "This channel could not be saved on this device. The app keeps trying; free some space if the device is full.";
  - while `ChannelStatus::storage_full`: "This channel's storage on this device is full. New messages wait on the server until older ones expire here.".
  The client MUST re-read as spec 027-core-api R14 says: `channels()` and `status()` after a `StatusChanged` for a channel it does not list or whose `write_failed` it shows, after every successful import and after every settings call that returns `Ok`; otherwise the channel's `channel_status`, `peers`, `messages` and `gaps`, at most once every 1 000 ms, at the screen's tick, for every channel marked by a `StatusChanged` or a `Message`; and all of those after `StorageFailed` and after a call that returned `Error::Store`.
- R12 The composer MUST send with `send(channel, body, display_name)` and:
  - be disabled while the body is empty, and while `read_only` is set, with the text of spec 055-verify-ui R11;
  - when `own_display_name` is `None`, ask before the first send "Your name in this channel", with "Everyone in this channel sees this name. Use a different one in each channel if you do not want them linked.", checked for shape as spec 055-verify-ui R15 checks a label, and pass it as `Some(name)`; otherwise pass `None`, which keeps the stored name (spec 021-channel-session R7). The channel card's "Change your name in this channel" passes the new name with the next send and says "Used from your next message";
  - keep the body in the composer until `send` returns `Ok`, and clear it then; the draft lives in the screen's state only and is dropped at lock (spec 053-device-security R21);
  - map errors once: `Store(OutboxFull)` "Too many messages are waiting to be sent. Wait until some are sent."; `CounterExhausted` "This key cannot send more messages. Regenerate your key to write again."; `RetiredKey` the text of spec 055-verify-ui R11; `BadPayload` "This message is too long."; `Store(LogFull)` the storage text of R11; any other `Store` reason "The message could not be saved on this device.", with R11's re-read; `UnknownChannel` a re-read of `channels()`; `Locked` nothing, since the lock screen shows; any other "Something went wrong. Try again.".
  On the phones, the composer's keyboard follows spec 053-device-security R15.

**The channel card**

- R13 The channel card MUST show the channel's name with "Rename", its server and lifetime as read-only values (spec 054-qr-invite R3), "Your name in this channel" with its change action (R12), the actions of spec 054-qr-invite ("Show invitation", "Send invitation file", "Create new channel"), the members (`peers`, each opening its peer card of spec 055-verify-ui), "Verify" (the verification screen of spec 055-verify-ui R17), the key actions of spec 055-verify-ui R14 and R16, and "Leave channel" last. "Rename" takes 0..=64 bytes of UTF-8 with no Cc character, checked for shape; an empty name calls `rename_channel(channel, "")`, which goes back to the invitation's name; `BadPayload` shows "Names cannot be empty or longer than 64 bytes".
- R14 "Leave channel" MUST first show a destructive confirmation: "Leaving deletes this channel's messages, keys and members from this device, and stops its subscription. To come back you need a new invitation." (`docs/spec.md` §7 "Leave channel"), with "Leave channel" and "Cancel", and only then call `leave(channel)`. On `Ok` the client goes to the channel list; a `Store` error shows "The channel could not be deleted from this device. Try again.", with R11's re-read.

**Settings and help**

- R15 Settings MUST offer:
  - "Default server for new channels", saved with `set_default_server_url`; `BadConfig` shows "This is not a valid server address.";
  - "Lock after", with "Immediately" (0), "1 minute" (60, the default), "5 minutes", "15 minutes" and "1 hour", saved with `set_lock_timeout_seconds` through spec 053-device-security R7 on Android, and directly elsewhere, with the platform's meaning stated under it: on the phones "The app always locks when you leave it; this is how long returning to it skips the prompt.", on the desktop "The app locks when its window has been in the background this long.";
  - "Tor proxy (SOCKS5)", a field for `host:port` or empty, saved with `set_socks5_proxy` (R16);
  - "Erase all data on this device" (R17);
  - "Help" (R18) and the app's version.
- R16 Before a change of the proxy is saved, the client MUST confirm it, naming what changes: to no proxy, "Without a proxy, every server sees this device's IP address, and onion channels stop connecting."; to a proxy whose host is not a loopback IP literal, "This proxy is on another computer: it sees which servers this device talks to."; to a loopback proxy, no confirmation. On the desktop the native confirmation of spec 041-desktop-bridge R16 replaces this one. `BadConfig` shows "Write the proxy as host and port, like 127.0.0.1:9050." and, when the host is `localhost`, "Use 127.0.0.1, not localhost.".
- R17 "Erase all data on this device" MUST first show a destructive confirmation: "This deletes every channel, key and message on this device. It cannot be undone. To come back to a channel you need a new invitation." Only then does the client erase: `reset_local_data` on the desktop (spec 041-desktop-bridge R16, whose native confirmation replaces this one), `LockController.reset()` on the phones (spec 053-device-security R23). The app then shows the Locked screen.
- R18 Help MUST be a screen reachable from the channel list and from Settings, with these sections, in this order, each a fixed text of the string resources:
  - "What this app protects, and what it does not": the two lists of `docs/spec.md` §1, "What it promises" and "What it does not promise", word for word, in that order;
  - "Locking": "Set a screen lock on this device and prefer a PIN or password to a fingerprint or face. The app locks when you leave it, and a desktop window left open and unattended stays unlocked: lock your computer when you step away.";
  - "Backups": "Nothing this app keeps goes into backups. A new phone, a restored backup or a reinstall starts empty: ask a member for a new invitation to each channel.", and on the desktop "Exclude this app's data folder from File History, Time Machine or any other backup tool.";
  - "Tor": "To hide your IP address from servers, run Tor (on Android, Orbot) and set its SOCKS5 proxy in Settings, usually 127.0.0.1:9050. Onion servers work only through such a proxy.";
  - on the desktop only, "Notifications and clipboard": "Notifications say only \"New messages\", and only until the app locks. A copied message stays on the clipboard for one minute. On Linux, screen capture cannot be blocked." (spec 053-device-security R12–R14).

**Tests**

- R19 Each platform MUST test the functions of R1 against every row of `clients/fixtures/chat_presentation.json`, which MUST hold at least one row for each case of R8, R9, R10 and R11, and MUST have one UI test of the flow "write and read" with a fake core: open a channel, give a name at the first send, see the row go from "Waiting to send" to "Sent" on a `Delivered`, receive a peer's message by a `Message` event, and see it leave the screen at its `expires_at`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| A body typed by the user | not empty; the core bounds its size (spec 013-wire-message R10) | Send disabled; `BadPayload` from the core, R12's text |
| The user's name in a channel, a channel name | 1..=64 bytes of UTF-8, no Cc (0..=64 for a rename) | the shape text, no call; `BadPayload` from the core, the same text |
| `sent_at` against `received_at` | within 300 000 ms | the "Sent at … by the sender's clock" mark |
| Re-reads of a channel | at most one per 1 000 ms, at the tick | merged into the next tick |
| Expired rows | removed when `expires_at` ≤ `now`, checked every 1 000 ms | — |

## Interface

```
clients/fixtures/chat_presentation.json   R1: records, events and now → the presentation model
clients/android/app/src/main/kotlin/org/privatechat/ui/chat/        Presentation.kt (R1), ChannelListScreen.kt, ChannelScreen.kt, ChannelCard.kt, SettingsScreen.kt, HelpScreen.kt, NoticeScreen.kt
clients/android/app/src/main/kotlin/org/privatechat/viewmodel/      ChannelListViewModel.kt, ChannelViewModel.kt, SettingsViewModel.kt
clients/ios/Privatechat/Views/Chat/                                  Presentation.swift (R1), ChannelListView.swift, ChannelView.swift, ChannelCard.swift, SettingsView.swift, HelpView.swift, NoticeView.swift
clients/ios/Privatechat/ViewModels/                                  ChannelListModel.swift, ChannelModel.swift, SettingsModel.swift
clients/desktop/src/lib/ui/chat/                                     present.ts (R1), ChannelList.svelte, Channel.svelte, ChannelCard.svelte, Settings.svelte, Help.svelte, Notice.svelte
clients/desktop/src/lib/state/                                       channels.svelte.ts, channel.svelte.ts, settings.svelte.ts
```

The presentation model, the same on every platform (field names in each language's case):

```
ChannelRowView { name: Text | Placeholder, newMessages: bool, connection: ConnectionLine | none, couldNotSave: bool }
MessageView    { key: ServerId | ClientRef, sender: SenderView, time, sentAtMark: time | none,
                 body: Text | KeyRetired | Unreadable, delivery: Waiting | Sent | NotSent | none, actions: [Copy, SendAgain] }
GapView        { sender: SenderView, missing: n | none, anomalous: bool }
ConnectionLine = NeedsProxy { useLoopbackHint } | Connecting | Retrying | ServerFull | UnsupportedServer | ProxyRefused | Failed
BannersView    { refused: bool, full: bool, couldNotSave: bool, storageFull: bool, truncatedBefore: time | none }
```

Screen state and intents (architecture skill §7):

```
AppState          = Locked | SettingsNotice(reason) | Channels(ChannelListState) | Channel(id, ChannelState) | Card(id) | Settings | Help
ChannelListState  = Loading | Ready { rows, broken } | Failed(kind)
ChannelListIntent = Open(id) | Create | Join | RemoveBroken(name) | Settings | Help | LockNow
ChannelState      = Loading | Ready { header, banners, gaps, rows, composer } | Failed(kind)
ChannelIntent     = Type(text) | Send | GiveName(name) | Copy(key) | SendAgain(key) | OpenCard | Tick
CardIntent        = Rename(name) | ChangeOwnName(name) | Leave | ConfirmLeave | Cancel
SettingsIntent    = SetDefaultServer(url) | SetLockAfter(seconds) | SetProxy(text) | ConfirmProxy | EraseAll | ConfirmErase | Cancel
NoticeIntent      = CheckSettings | Continue | Replace | ConfirmReplace
```

Test names: each T below is `s056_tTT_rRR_<name>`, spelled on each platform as spec 055-verify-ui gives.

**PR slices** (AGENTS 14), per platform: (a) the fixture and the functions of R1 with their tests (R1–R3, R8–R11); (b) the notices, the channel list and the channel screen with the composer (R4–R7, R12); (c) the card, settings and help (R13–R18); (d) the UI test (R19).

## Security

- Nothing on these screens decides trust or protocol (R1); a wrong presentation draws a wrong line, it cannot accept a message the core refused or make one appear sent.
- No text from a peer is markup, and no link in it is followed, previewed or fetched (R2), so a message cannot run code in the desktop's web view, open a browser, or tell a server, through a preview's request, that it was read.
- The "new messages" marks, the connection states, the banners and the draft are held in memory and dropped at lock (R6, R10–R12, spec 053-device-security R21); nothing of a channel is saved by the platform.
- The name the user gives in a channel travels to its members inside every message (spec 021-channel-session). The prompt says so and suggests a different name per channel, since the same name in two channels links them for anyone in both (`docs/spec.md` §7).
- Dropping or moving the proxy is confirmed with what it exposes (R16), so a slip of the settings does not silently send a Tor user's traffic in the clear.
- "Sent" says the server took the message, never that anyone read it (R8); the app has no read receipts.

## Public API changes

None. These screens use `Device` through spec 040-uniffi on the phones and spec 041-desktop-bridge on the desktop, as they stand, with the host's events and states of spec 042-connection-host.

## Test cases

- T01 (covers R1): `s056_t01_r01_presentation_fixture`: every row of the fixture gives its expected model on each platform; the functions touch no core method.
- T02 (covers R2): `s056_t02_r02_text_only`: a body of `<b>x</b> https://example.org` is drawn as those characters, with no link and no request; a body with three lines keeps them.
- T03 (covers R3): `s056_t03_r03_strings`: every string key of this spec exists in the English resources with the texts of R4–R18 and in each UI language; a time today and one last week are formatted by the locale.
- T04 (covers R4): `s056_t04_r04_settings_notice`: with `settings_reset` and each reason, the notice shows its text and blocks the list; "Continue" calls `acknowledge_settings(false)` and re-reads; "Replace settings" appears only for `UnsupportedVersion` and calls `acknowledge_settings(true)` only after its confirmation.
- T05 (covers R5): `s056_t05_r05_broken`: each reason gives its text and action; a declined confirmation calls nothing; `UnknownChannel` re-reads `status()`.
- T06 (covers R6): `s056_t06_r06_channel_list`: rows in the core's order; a `Message` event marks a channel not on screen, opening it clears the mark, and a lock clears every mark; the empty text with no channel.
- T07 (covers R7): `s056_t07_r07_message_list`: rows in the core's order, keyed by `server_id` or `client_ref`; a `Delivered` updates the own row in place; a row is gone within 1 000 ms after its `expires_at`; a lifetime of 604 800 s reads "7 days".
- T08 (covers R8): `s056_t08_r08_message_rows`: fixture rows for each content kind and delivery state, a `sent_at` 301 000 ms from `received_at` (the mark) and one 299 000 ms away (none); "Send again" sends the same body and leaves the old row "Not sent"; a text row has "Copy" and no native selection.
- T09 (covers R9): `s056_t09_r09_gaps`: fixture rows for a gap of 3, an anomalous gap (the §4 text) and a gap with `spans_truncation` (drawn as the plain gap); `truncated_before` shows §6's text with its date.
- T10 (covers R10): `s056_t10_r10_connection`: fixture rows for every state, `needs_proxy` with a `localhost` proxy (the hint) and with none, and no state since unlock ("Connecting…"); a lock drops the states.
- T11 (covers R11): `s056_t11_r11_banners_and_rereads`: `SubscribeRefused` shows its banner until `Subscribed`; `ChannelFull` until `Delivered`, with the create action; `write_failed` and `storage_full` show theirs; 30 `StatusChanged` events within one second give one re-read; `StorageFailed` re-reads everything at once.
- T12 (covers R12): `s056_t12_r12_composer`: empty body → Send disabled; no `own_display_name` → the name asked, with its text, then `send` with `Some(name)`; the next `send` with `None`; a changed name goes with the next send; each error of R12 shows its text and keeps the draft; a lock drops the draft.
- T13 (covers R13): `s056_t13_r13_card`: the card lists the actions of R13 in order, server and lifetime not editable; a rename to "" calls `rename_channel` with ""; a 65-byte name shows the text with no call.
- T14 (covers R14): `s056_t14_r14_leave`: the confirmation's text, "Cancel" calls nothing, "Leave channel" calls `leave` and returns to the list; a `Store` error shows its text.
- T15 (covers R15): `s056_t15_r15_settings`: each setting calls its setter; `BadConfig` for the server shows its text; the lock choices are exactly the five of R15 with 60 preselected on a fresh device, and the platform's line under them.
- T16 (covers R16): `s056_t16_r16_proxy`: to none → the no-proxy text before the save; to `10.0.0.2:9050` → the other-computer text; to `127.0.0.1:9050` → no confirmation; a declined confirmation saves nothing; `localhost:9050` → `BadConfig` with the hint.
- T17 (covers R17): `s056_t17_r17_erase`: the confirmation's text; a cancel erases nothing; a yes calls the platform's erase and shows the Locked screen.
- T18 (covers R18): `s056_t18_r18_help`: the sections in order; the first section's English strings equal the two lists of `docs/spec.md` §1 read from the repository; the desktop-only section is absent on the phones.
- T19 (covers R19): `s056_t19_r19_write_and_read`: the UI test of R19 on each platform: Compose UI test, XCTest UI test, `@testing-library/svelte`.

## Vectors

None. The fixture of R1 is UI data, not a protocol vector: it is not frozen by AGENTS 18 and changes with this spec.

## Acceptance criterion

On each platform, the tests of T01–T19 green in CI (Android: `./gradlew test connectedCheck` on an emulator; iOS: `xcodebuild test`; desktop: `pnpm test`). Non-automatable, and the phase 5 exit criterion of `docs/spec.md` §10: one user on the desktop, one on Android and one on iOS join the same channel from one invitation (the phones by QR, the desktop by file) and each reads the others' messages; a second person reads every text of R4–R18 in English and one other UI language and does a screen-reader pass over the channel list and a channel.

## Out of scope

- Where the screens sit, the navigation and the look of each app (specs 050-desktop-mvp, 051-android-mvp, 052-ios-mvp).
- Unlocking, the lock and `KeyLost` (spec 053-device-security); invitations, the scanner and joining (spec 054-qr-invite); peers, trust and verification (spec 055-verify-ui).
- Deleting a single message locally, editing, replying, quoting, reactions, read receipts, presence and attachments: none is in v1 (`docs/spec.md` §1, §12).
- Search: a search index would be one more copy of the content outside the core.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 5 drafts", Q11)
