# 050 — Desktop app: the Svelte UI over the bridge

Status: draft
Phase: 5
Related ADRs: 0017, 0037, 0041
Depends on: 041-desktop-bridge, 042-connection-host, 053-device-security, 054-qr-invite, 055-verify-ui, 056-chat-screens
Blocks: 060-reproducible-builds, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Spec 041-desktop-bridge defines the Rust side of the Tauri process: the commands, the events, the web view's hardening, the keychain and the native confirmations. Specs 053–056 define what the three clients share. This spec is the rest of the desktop app: the Svelte 5 page in `clients/desktop/src/`, how it lays out the screens of 053–056 in one window, how it calls the bridge and listens to its events, the rules the page must keep so that the bridge's defences hold (text as text, no network, no storage, copy through the bridge), and its build, lint and tests. The web view is the least trusted part of the process (typescript-svelte skill): nothing here holds a key, a socket or a file.

**In plain words.** The computer app is one window: the list of channels on the left, the open channel on the right. The page only draws and asks the Rust side for things by name. It cannot reach the internet, keeps nothing on disk, and never unlocks by itself: the user clicks "Unlock" and answers the system's prompt. When a system dialog is waiting, the page says so, so that nobody thinks the app froze.

## Requirements

**The page and the bridge**

- R1 The page MUST be a Svelte 5 app in `clients/desktop/src/` with the layout of the typescript-svelte skill (`lib/ui/`, `lib/state/`, `lib/bridge/`), TypeScript `strict`, and runes only. `src/lib/bridge/` MUST be the only code that calls `invoke` or `listen`: the generated `commands` of spec 041-desktop-bridge R5, the hand-written wrappers of its raw commands (041 R6), and one listener each for `core-event`, `connection-state` and `locked` (041 R7), which hand every event to the state modules through one typed dispatcher. An ESLint rule (`no-restricted-imports` of `@tauri-apps/api/core` and `@tauri-apps/api/event` outside `src/lib/bridge/`) MUST enforce it.
- R2 The dispatcher MUST route every `core-event` by its `channel` to the state of that channel and to the channel list (spec 056-chat-screens R6, R7, R11), every `connection-state` to the app's state map (056 R21), whether or not the channel is listed yet, and `locked { fault }` to the app state, which MUST drop every state module's data and show the Locked page before anything else runs (spec 053-device-security R21); a `locked` always moves the page to locked, whoever started the lock. After `locked` the page is gone: the bridge recreates the window at every lock and reset (spec 041-desktop-bridge R17), and the page never takes part in that. The page does not filter by generation: the bridge forwards nothing of an older generation (spec 041-desktop-bridge R7). An event for a channel the page does not list marks one coalesced re-read of `channels()` and `status()`, issued at the next tick of 056 R11 and never while the first list read is pending. Every state module records the unlock epoch of 056 R21 when it calls a command and drops a result that returns under another epoch. At mount, the page of each new window MUST call `status()`: `Ok` means the device is unlocked (a reload that raced an unlock, a crashed web process), so the page goes to the channel list and reads `connection_states()` into the map; `Locked` shows the Locked page. It then calls `take_lock_notice()` (spec 041-desktop-bridge), which works while locked and returns at most one `LockNotice` kept by the bridge across the new window: `Fault { recurring }` shows the fault text of spec 056-chat-screens R20, with its erase offer when `recurring` is true, and `ResetIncomplete` shows "The data could not be fully deleted." on the Locked page. An `unlock` that returns `ReloadPending` (the new window has not finished loading) shows "Reloading, try again in a moment." and changes nothing else.
- R3 The page MUST NOT reach the network or keep anything: no source under `src/` names `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `navigator.sendBeacon`, `localStorage`, `sessionStorage`, `indexedDB`, `caches` or `document.cookie`, enforced by ESLint's `no-restricted-globals` and `no-restricted-properties`; the CSP of spec 041-desktop-bridge R8 is the second line. The page ships every asset in the bundle, fonts included, and loads nothing from another origin.
- R4 Every text from a peer, a name and a label MUST be rendered by Svelte's text interpolation (`{value}`), never by `{@html}`, `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`: ESLint's `svelte/no-at-html-tags` and a `no-restricted-properties` rule MUST fail on them anywhere under `src/`. Message text MUST carry `user-select: none`, and the page MUST route the `copy` event and the Edit menu's Copy to the bridge's `copy_message(channel, kind, id)` with the channel and the id of the row that has the keyboard focus: an own row always as `Client` with its `client_ref`, whether delivered or not and whatever its `server_id`; a peer's row as `Server` with its `server_id`; nothing when no message row has the focus, never a text, and nothing for a peer's row keyed by its position (056 R8), which the bridge refuses as ambiguous, so that the Rust side reads the body from the core and the web view never writes the clipboard itself (spec 053-device-security R14).

**The window**

- R5 The one window MUST lay out the channel list (spec 056-chat-screens R6) on the left and the open channel, its card, settings or help on the right, with the list collapsing below a width of 720 CSS pixels into a single pane with a back action. The Locked page, the settings notice (056 R4), the `KeyLost` screen (spec 053-device-security R5) and the screens that show a secret (the invitation QR, the seven words, specs 054-qr-invite R6, R7, R10) MUST fill the whole window, never a dialog or a pane.
- R6 The Locked page is the Locked screen of spec 056-chat-screens R20, whose "Unlock" calls `unlock`. The page MUST NOT call `unlock` without that click: not at start, not on focus, not after a `locked` event, not on a timer (spec 053-device-security R8). `Cancelled` and a declined prompt leave the page as it is; `KeyLost` opens the desktop `KeyLost` screen: the text of spec 053-device-security R5 with its one action, "Erase all data on this device", which calls `reset_local_data` behind the native confirmation of spec 041-desktop-bridge R16; `KeychainUnavailable` shows "The system keychain is not available. Unlock your session's keychain and try again."; `AlreadyRunning` shows "The app is already open in another window."; `FileIo` shows "The app's data folder could not be read."; `Core(_)` and a `locked` with its fault set, or a `Fault { recurring }` notice at mount, show the texts of 056 R20, with its erase action only where 056 R20 offers it (a `recurring` fault, or an unlock failing with `Internal`, `Corrupt` or `UnsupportedVersion`), which calls `reset_local_data`; `ReloadPending` shows R2's text.
- R7 While a command that can open a native dialog or a system prompt is pending (`unlock`, `reset_local_data`, `choose_chatcfg`, `export_file`, and every command that spec 041-desktop-bridge R16 confirms), the page MUST show "Answer the system dialog to go on." and accept no other action that could open one, since on Linux the dialog can fall behind the window (041 Security). `Suppressed { retry_after_ms }` MUST show "Try again in {seconds} s." with the seconds rounded up, `DialogOpen` (a native dialog from before a reload or a lock is still open, spec 041-desktop-bridge R9) MUST show "Answer the system dialog to go on.", and `Cancelled` changes nothing.
- R8 The keyboard MUST reach every action (typescript-svelte skill), with these keys: Enter sends and Shift+Enter breaks the line in the composer; Escape closes the open card, settings or help and cancels an in-page confirmation; `CmdOrCtrl+L` is the bridge's "Lock now" menu item (spec 053-device-security R10), which the page does not handle itself.

**Language, look and access**

- R9 Strings MUST come from `src/lib/i18n/{en,es,fr,ca,it}.json` through one `t(key, params)`, with English as the source and the locale chosen from `navigator.languages` at start, falling back to English; a test MUST fail when a key of `en.json` is missing from another file or a placeholder differs. Dates and times use `Intl.DateTimeFormat` in that locale (spec 056-chat-screens R3).
- R10 The page MUST follow the system's light or dark scheme (`prefers-color-scheme`) and reduced motion (`prefers-reduced-motion`), use one global file of CSS custom properties for colours, among them the primary and secondary text colours that spec 055-verify-ui R4–R7 name, and keep every text at a contrast of at least 4.5:1 against its background in both schemes. Every icon button has an `aria-label`, focus is always visible, and the verified icon of spec 055-verify-ui R6 is an inline SVG of the bundle, never a character a name could contain.

**Build and tests**

- R11 `clients/desktop/package.json` MUST pin Node in `.nvmrc`, use `pnpm` with a committed `pnpm-lock.yaml`, and run no `postinstall` script that fetches. The CI job `desktop` of spec 041-desktop-bridge R14 MUST also run, in this order: `pnpm install --frozen-lockfile` in `clients/desktop/`; the generation of `generated.ts` with `cd clients/desktop/src-tauri && cargo test export_bindings`, from inside the Cargo workspace (spec 042-connection-host R15); then, in `clients/desktop/`, `pnpm check` (`svelte-check` and `tsc --noEmit`), `pnpm lint` (ESLint and Prettier), `pnpm test` (Vitest) and `pnpm build`, and `.github/CONTRIBUTING.md` MUST list them (AGENTS 17).
- R12 The state modules MUST be tested with Vitest over an in-memory fake of the bridge's typed interface, never over Tauri's IPC, and the UI flows of specs 054-qr-invite (import a config), 055-verify-ui (verify a peer) and 056-chat-screens (write and read) with `@testing-library/svelte`.

**Platforms and access**

- R13 The desktop app MUST support exactly these systems, fixed as of 2026-09-28 and checked again when this spec is accepted and at each bump of spec 065-release-maintenance R4: macOS 15 or later (`bundle.macOS.minimumSystemVersion = "15.0"`), Windows 11 on x86-64, and Linux on x86-64 with WebKitGTK 4.1 and the glibc of the Linux build image of spec 060-reproducible-builds R2, which the `.deb` declares as the dependencies Tauri's bundler writes and the landing's download page names; no arm64 Linux build, since spec 060-reproducible-builds builds none. `bundle.windows.webviewInstallMode` MUST be `{ "type": "skip" }`: the installer neither downloads WebView2 at install time nor carries a Microsoft installer that spec 060-reproducible-builds would have to commit under `vendor/bundler/`, since Windows 11 ships the WebView2 runtime. The page's JavaScript and CSS MUST need nothing newer than the web engines of those systems (Safari 18's WebKit, WebView2's current Chromium, WebKitGTK 4.1), the `build.target` of `vite.config.ts` set to match.
- R14 Every screen MUST be usable with the keyboard and a screen reader alone, beyond R8 and R10: the focus order follows the visual order; opening a screen or a card moves the focus to its heading, and closing it returns the focus to where it was; an in-page confirmation keeps the focus inside it until it is answered; every control has an accessible name and every state change (pending, sent, not delivered, verified) is exposed as text, never as colour alone. The announcement of a new message MUST be the one of spec 056-chat-screens R7, through one `aria-live="polite"` region; the user reads the message by moving to it.
- R15 At start, before the window is created, the app MUST read the WebView2 runtime's version through Tauri's `webview_version()` and, when it fails, show through `rfd`, in the translated build-time strings of the bridge's dialogs (spec 041-desktop-bridge), the fixed text "This app needs the Microsoft Edge WebView2 runtime, which Windows 11 includes. Download it from Microsoft's WebView2 page and start the app again." and exit without creating a window.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Window width | ≥ 720 CSS px for two panes | one pane with a back action |
| `Suppressed` wait | `retry_after_ms` from the bridge | shown in whole seconds, rounded up |
| Text contrast | ≥ 4.5:1 in both schemes | a failing test |
| System | macOS ≥ 15; Windows 11 x86-64; Linux x86-64 with WebKitGTK 4.1 and glibc ≥ that of the build image | not supported; on Windows without WebView2, R15's text and exit |

## Interface

```
clients/desktop/package.json, pnpm-lock.yaml, .nvmrc, vite.config.ts, svelte.config.js, eslint.config.js, tsconfig.json
clients/desktop/src/App.svelte                   the window layout (R5) and the app state
clients/desktop/src/lib/bridge/dispatch.ts       the three listeners and the typed dispatcher (R1, R2)
clients/desktop/src/lib/bridge/pending.svelte.ts the pending-dialog state (R7)
clients/desktop/src/lib/ui/Locked.svelte         R6
clients/desktop/src/lib/i18n/{en,es,fr,ca,it}.json, t.ts   R9
clients/desktop/src/styles/tokens.css            R10
clients/desktop/tests/                           Vitest and @testing-library/svelte (R12)
```

```ts
// src/lib/bridge/dispatch.ts
export type Dispatch = {
  coreEvent(event: BridgeEvent): void;                 // the generated mirror of the host's event (spec 041-desktop-bridge R5, R7); routed by channel (R2)
  connectionState(channels: ReadonlyArray<ChannelId>, state: ConnectionState): void;
  locked(fault: boolean): void;                        // drops every state module's data first; fault shows 056 R20's text
};
export function listenAll(dispatch: Dispatch): Promise<() => void>;   // the only listen calls of the page
```

The screens themselves, their states and intents are those of specs 053-device-security, 054-qr-invite, 055-verify-ui and 056-chat-screens, in the files they name under `clients/desktop/src/lib/`.

Test names: `s050_tTT_rRR_<name>` in the Vitest `test` title, as the typescript-svelte skill gives.

**PR slices** (AGENTS 14): (a) the project, the lint rules, the i18n, the CI steps the supported systems and the WebView2 check (R1, R3, R4, R9, R11, R13, R15); (b) the dispatcher, the app state and the Locked page (R2, R6, R7); (c) the window layout, the keys, the look and access (R5, R8, R10, R14); (d) the tests of R12. The screens of 053–056 land in their own slices, inside this app.

## Security

- The page holds what the user reads and types, and nothing else (spec 041-desktop-bridge, Security). An injected script keeps the power of the UI, which is 041's documented residual; this spec keeps scripts from getting in: no markup from any text (R4), no network and no storage (R3), everything from the bundle (R3), and the CSP of 041 R8 behind them.
- The page never unlocks on its own (R6), so a lock by the timer never raises Touch ID or Windows Hello over another application (spec 053-device-security R8).
- Copy goes through the bridge by channel and row key (R4), so the clipboard holds the text of a message the core holds, for 60 s; an injected script can still choose which message is copied and when, within the power of the UI (spec 041-desktop-bridge, Security), but not put a text of its own there.
- The verified icon is an image, not a character (R10), which with spec 055-verify-ui R2 keeps a name from imitating it.
- The installer downloads nothing (R13), so every byte it installs is in the reproducible build; what Windows itself tells Microsoft about a downloaded installer (SmartScreen) is in the privacy policy of spec 062-security-docs R2.
- The "New message" announcement carries no name and no body (R14, spec 056-chat-screens R7), like the notification of spec 053-device-security R13; a screen reader still speaks whatever the user moves to, including message bodies and the seven words of an export, which is spec 053-device-security's documented residual.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s050_t01_r01_bridge_only`: ESLint fails on a fixture file under `src/lib/ui/` that imports `invoke`, and passes on the real tree.
- T02 (covers R2): `s050_t02_r02_dispatch`: a `core-event` `Message` reaches its channel's state and marks the list; a `connection-state` for a channel not yet listed is shown once it is listed; a `messages` result that returns after `locked` changes nothing; end to end over a fake bridge that filters as 041 R7 says, a lock and an unlock in quick succession leave the page unlocked and showing only the new unlock's states; a `locked` the page did not start moves it to Locked; 200 `core-event`s for an unlisted channel give one `channels()` re-read at the next tick; mounting while unlocked goes to the list and reads `connection_states()`; `take_lock_notice` at mount giving `ResetIncomplete` shows its text, giving `Fault { recurring: false }` shows the fault text with "Unlock" only, and giving `Fault { recurring: true }` adds the erase action; `ReloadPending` from `unlock` shows its text; `locked` empties every state module and shows the Locked page before the next microtask; an event for an unknown channel re-reads `channels()` and `status()`.
- T03 (covers R3): `s050_t03_r03_no_network_no_storage`: ESLint fails on fixtures that use `fetch`, `localStorage` or `document.cookie`, and `pnpm build` output references no other origin.
- T04 (covers R4): `s050_t04_r04_text_only`: ESLint fails on `{@html}` and on `innerHTML`; a message body of `<img src=x onerror=alert(1)>` is drawn as text; a `copy` event and Edit → Copy call `copy_message` with the channel and the focused row: an own row as `Client` with its `client_ref`, also when its `server_id` repeats another row's, a peer's row as `Server`; never a text, none when no row has the focus and none for a peer's position-keyed row, and writes nothing to the clipboard from the page.
- T05 (covers R5): `s050_t05_r05_layout`: two panes at 1 024 px and one at 700 px with a back action; the QR and the seven words fill the window.
- T06 (covers R6): `s050_t06_r06_locked_page`: mounting the app, focusing it and receiving `locked` never call `unlock`; a click does, once; each error shows its text, and `Core(Internal)` offers the erase action of 056 R20; a first `locked { fault: true }` shows the fault text with "Unlock" only; `KeyLost` shows the desktop `KeyLost` screen, whose erase calls `reset_local_data`.
- T07 (covers R7): `s050_t07_r07_pending_dialog`: while `export_file` is pending the text shows and a second dialog command is refused by the page; `Suppressed { retry_after_ms: 1 200 }` shows "Try again in 2 s."; `DialogOpen` from `unlock` shows "Answer the system dialog to go on."
- T08 (covers R8): `s050_t08_r08_keys`: Enter sends, Shift+Enter adds a line, Escape closes the card.
- T09 (covers R9): `s050_t09_r09_i18n`: a key missing from `ca.json`, or a placeholder renamed, fails; a `navigator.languages` of `["ca-ES"]` gives Catalan, `["de"]` English.
- T10 (covers R10): `s050_t10_r10_look`: the tokens give at least 4.5:1 for the primary and secondary text colours in both schemes; every icon button has an `aria-label`; the verified icon is an SVG element.
- T11 (covers R11): CI step `s050_t11_r11_desktop_ui_job`, which runs the commands of R11; `.github/CONTRIBUTING.md` lists them.
- T12 (covers R12): `s050_t12_r12_flows`: the three UI flows of R12 pass over the fake bridge.
- T13 (covers R13): `check_s050_t13_r13_platforms`: `tauri.conf.json` sets `minimumSystemVersion` `15.0` and `webviewInstallMode` `skip`, the bundle targets no arm64 Linux, and `vite.config.ts` a `build.target` no newer than R13's engines; non-automatable, the `.deb` installs on the build image's Debian and the app starts on macOS 15 and Windows 11.
- T14 (covers R14): `s050_t14_r14_access`: opening a card moves the focus to its heading and closing it returns it; an in-page confirmation keeps Tab inside; a pending and a not-delivered row expose their state as text; three messages from a peer within 2 000 ms while the focus is on the composer give one "New message" in the live region, with no name or body, and a muted peer's gives none (spec 056-chat-screens R7).
- T15 (covers R15): `s050_t15_r15_webview_missing`: with a fake `webview_version()` that fails, the app shows R15's text and opens no window.

## Vectors

None.

## Acceptance criterion

`pnpm check`, `pnpm lint`, `pnpm test` and `pnpm build` green in `clients/desktop/`, and the CI job `desktop` green. Non-automatable: on macOS, Windows and Linux, a person unlocks, joins a channel by file, chats with a phone, locks with `CmdOrCtrl+L`, and checks that the page never raised the system prompt on its own; a screen-reader pass (VoiceOver, Narrator, Orca) over the Locked page and a channel.

## Out of scope

- The Rust side of the Tauri process, its commands and its window configuration (spec 041-desktop-bridge).
- The screens' rules (specs 053-device-security, 054-qr-invite, 055-verify-ui, 056-chat-screens).
- Signing, notarisation, installers and reproducible builds (spec 060-reproducible-builds).
- A system tray icon, a start at login and more than one window: none is in v1.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 5 drafts", Q9 and Q11)
- 2026-09-27 revised after audit N round 1 (`docs/audit-log.md`): copy by channel and row key; connection states to the app's state map and results dropped across a lock; the Locked page as 056 R20, with `Core(_)` mapped; the host's event type named
- 2026-09-27 revised after audit N round 2 (`docs/audit-log.md`): events of an older generation ignored; one coalesced re-read for unlisted channels; `status()`, `connection_states()` and `take_reset_outcome` at mount; copy by key kind and id, none for position-keyed rows; a desktop `KeyLost` screen; `DialogOpen`
- 2026-09-27 revised after audit N round 3 (`docs/audit-log.md`): no generation filter in the page, the bridge's alone; `locked { fault }` and `take_lock_notice` at mount; `ReloadPending`; copy of the focused row; the CI order with the bindings generated from inside the workspace
- 2026-09-27 revised after audit N round 4 (`docs/audit-log.md`): the page is gone after `locked`, since the bridge recreates the window; `Fault { recurring }` at mount; own rows copied by `client_ref`
- 2026-09-28 revised after audit P (`docs/audit-log.md`): the supported systems and WebView2 with no download at install time (R13, D4); keyboard and screen-reader use with a "New message" announcement that names nothing (R14)
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): fixed, dated floors (macOS 15, Windows 11, Linux x86-64 only); the WebView2 check its own R15 with the download text corrected; no claim that installing tells Microsoft nothing; the announcement rule is 056 R7's
