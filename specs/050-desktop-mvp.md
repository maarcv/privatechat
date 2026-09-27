# 050 — Desktop app: the Svelte UI over the bridge

Status: draft
Phase: 5
Related ADRs: 0017, 0037, 0041
Depends on: 041-desktop-bridge, 042-connection-host, 053-device-security, 054-qr-invite, 055-verify-ui, 056-chat-screens
Blocks: —
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Spec 041-desktop-bridge defines the Rust side of the Tauri process: the commands, the events, the web view's hardening, the keychain and the native confirmations. Specs 053–056 define what the three clients share. This spec is the rest of the desktop app: the Svelte 5 page in `clients/desktop/src/`, how it lays out the screens of 053–056 in one window, how it calls the bridge and listens to its events, the rules the page must keep so that the bridge's defences hold (text as text, no network, no storage, copy through the bridge), and its build, lint and tests. The web view is the least trusted part of the process (typescript-svelte skill): nothing here holds a key, a socket or a file.

**In plain words.** The computer app is one window: the list of channels on the left, the open channel on the right. The page only draws and asks the Rust side for things by name. It cannot reach the internet, keeps nothing on disk, and never unlocks by itself: the user clicks "Unlock" and answers the system's prompt. When a system dialog is waiting, the page says so, so that nobody thinks the app froze.

## Requirements

**The page and the bridge**

- R1 The page MUST be a Svelte 5 app in `clients/desktop/src/` with the layout of the typescript-svelte skill (`lib/ui/`, `lib/state/`, `lib/bridge/`), TypeScript `strict`, and runes only. `src/lib/bridge/` MUST be the only code that calls `invoke` or `listen`: the generated `commands` of spec 041-desktop-bridge R5, the hand-written wrappers of its raw commands (041 R6), and one listener each for `core-event`, `connection-state` and `locked` (041 R7), which hand every event to the state modules through one typed dispatcher. An ESLint rule (`no-restricted-imports` of `@tauri-apps/api/core` and `@tauri-apps/api/event` outside `src/lib/bridge/`) MUST enforce it.
- R2 The dispatcher MUST route every `core-event` by its `channel` to the state of that channel and to the channel list (spec 056-chat-screens R6, R7, R11), every `connection-state` to the channels it names (056 R10), and `locked` to the app state, which MUST drop every state module's data and show the Locked page before anything else runs (spec 053-device-security R21), whatever the bridge's reload then does (041 R17). An event for a channel the page does not list makes it re-read `channels()` and `status()`.
- R3 The page MUST NOT reach the network or keep anything: no source under `src/` names `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `navigator.sendBeacon`, `localStorage`, `sessionStorage`, `indexedDB`, `caches` or `document.cookie`, enforced by ESLint's `no-restricted-globals` and `no-restricted-properties`; the CSP of spec 041-desktop-bridge R8 is the second line. The page ships every asset in the bundle, fonts included, and loads nothing from another origin.
- R4 Every text from a peer, a name and a label MUST be rendered by Svelte's text interpolation (`{value}`), never by `{@html}`, `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`: ESLint's `svelte/no-at-html-tags` and a `no-restricted-properties` rule MUST fail on them anywhere under `src/`. Message text MUST carry `user-select: none`, and the page MUST route the `copy` event and the Edit menu's Copy to the bridge's `copy_message` with the text of the message the user chose, never letting the web view write the clipboard itself (spec 053-device-security R14).

**The window**

- R5 The one window MUST lay out the channel list (spec 056-chat-screens R6) on the left and the open channel, its card, settings or help on the right, with the list collapsing below a width of 720 CSS pixels into a single pane with a back action. The Locked page, the settings notice (056 R4), the `KeyLost` screen (spec 053-device-security R5) and the screens that show a secret (the invitation QR, the seven words, specs 054-qr-invite R6, R7, R10) MUST fill the whole window, never a dialog or a pane.
- R6 The Locked page MUST show the app name, "Locked", and one action, "Unlock", which calls `unlock`. The page MUST NOT call `unlock` without that click: not at start, not on focus, not after a `locked` event, not on a timer (spec 053-device-security R8). `Cancelled` and a declined prompt leave the page as it is; `KeyLost` opens the screen of spec 053-device-security R5; `KeychainUnavailable` shows "The system keychain is not available. Unlock your session's keychain and try again."; `AlreadyRunning` shows "The app is already open in another window."; `FileIo` shows "The app's data folder could not be read."
- R7 While a command that can open a native dialog or a system prompt is pending (`unlock`, `reset_local_data`, `choose_chatcfg`, `export_file`, and every command that spec 041-desktop-bridge R16 confirms), the page MUST show "Answer the system dialog to go on." and accept no other action that could open one, since on Linux the dialog can fall behind the window (041 Security). `Suppressed { retry_after_ms }` MUST show "Try again in {seconds} s." with the seconds rounded up, and `Cancelled` changes nothing.
- R8 The keyboard MUST reach every action (typescript-svelte skill), with these keys: Enter sends and Shift+Enter breaks the line in the composer; Escape closes the open card, settings or help and cancels an in-page confirmation; `CmdOrCtrl+L` is the bridge's "Lock now" menu item (spec 053-device-security R10), which the page does not handle itself.

**Language, look and access**

- R9 Strings MUST come from `src/lib/i18n/{en,es,fr,ca,it}.json` through one `t(key, params)`, with English as the source and the locale chosen from `navigator.languages` at start, falling back to English; a test MUST fail when a key of `en.json` is missing from another file or a placeholder differs. Dates and times use `Intl.DateTimeFormat` in that locale (spec 056-chat-screens R3).
- R10 The page MUST follow the system's light or dark scheme (`prefers-color-scheme`) and reduced motion (`prefers-reduced-motion`), use one global file of CSS custom properties for colours, among them the primary and secondary text colours that spec 055-verify-ui R4–R7 name, and keep every text at a contrast of at least 4.5:1 against its background in both schemes. Every icon button has an `aria-label`, focus is always visible, and the verified icon of spec 055-verify-ui R6 is an inline SVG of the bundle, never a character a name could contain.

**Build and tests**

- R11 `clients/desktop/package.json` MUST pin Node in `.nvmrc`, use `pnpm` with a committed `pnpm-lock.yaml`, and run no `postinstall` script that fetches. The CI job `desktop` of spec 041-desktop-bridge R14 MUST also run, in `clients/desktop/`, `pnpm install --frozen-lockfile`, `pnpm check` (`svelte-check` and `tsc --noEmit`), `pnpm lint` (ESLint and Prettier), `pnpm test` (Vitest) and `pnpm build`, and `.github/CONTRIBUTING.md` MUST list them (AGENTS 17).
- R12 The state modules MUST be tested with Vitest over an in-memory fake of the bridge's typed interface, never over Tauri's IPC, and the UI flows of specs 054-qr-invite (import a config), 055-verify-ui (verify a peer) and 056-chat-screens (write and read) with `@testing-library/svelte`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Window width | ≥ 720 CSS px for two panes | one pane with a back action |
| `Suppressed` wait | `retry_after_ms` from the bridge | shown in whole seconds, rounded up |
| Text contrast | ≥ 4.5:1 in both schemes | a failing test |

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
  coreEvent(event: BridgeEvent): void;                 // routed by channel (R2)
  connectionState(channels: ReadonlyArray<ChannelId>, state: ConnectionState): void;
  locked(): void;                                      // drops every state module's data first
};
export function listenAll(dispatch: Dispatch): Promise<() => void>;   // the only listen calls of the page
```

The screens themselves, their states and intents are those of specs 053-device-security, 054-qr-invite, 055-verify-ui and 056-chat-screens, in the files they name under `clients/desktop/src/lib/`.

Test names: `s050_tTT_rRR_<name>` in the Vitest `test` title, as the typescript-svelte skill gives.

**PR slices** (AGENTS 14): (a) the project, the lint rules, the i18n and the CI steps (R1, R3, R4, R9, R11); (b) the dispatcher, the app state and the Locked page (R2, R6, R7); (c) the window layout, the keys and the look (R5, R8, R10); (d) the tests of R12. The screens of 053–056 land in their own slices, inside this app.

## Security

- The page holds what the user reads and types, and nothing else (spec 041-desktop-bridge, Security). An injected script keeps the power of the UI, which is 041's documented residual; this spec keeps scripts from getting in: no markup from any text (R4), no network and no storage (R3), everything from the bundle (R3), and the CSP of 041 R8 behind them.
- The page never unlocks on its own (R6), so a lock by the timer never raises Touch ID or Windows Hello over another application (spec 053-device-security R8).
- Copy goes through the bridge (R4), so the clipboard holds a copied message for 60 s and never anything the page chose to put there by script.
- The verified icon is an image, not a character (R10), which with spec 055-verify-ui R2 keeps a name from imitating it.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s050_t01_r01_bridge_only`: ESLint fails on a fixture file under `src/lib/ui/` that imports `invoke`, and passes on the real tree.
- T02 (covers R2): `s050_t02_r02_dispatch`: a `core-event` `Message` reaches its channel's state and marks the list; a `connection-state` reaches the channels it names; `locked` empties every state module and shows the Locked page before the next microtask; an event for an unknown channel re-reads `channels()` and `status()`.
- T03 (covers R3): `s050_t03_r03_no_network_no_storage`: ESLint fails on fixtures that use `fetch`, `localStorage` or `document.cookie`, and `pnpm build` output references no other origin.
- T04 (covers R4): `s050_t04_r04_text_only`: ESLint fails on `{@html}` and on `innerHTML`; a message body of `<img src=x onerror=alert(1)>` is drawn as text; a `copy` event on a message calls `copy_message` with its text and writes nothing to the clipboard from the page.
- T05 (covers R5): `s050_t05_r05_layout`: two panes at 1 024 px and one at 700 px with a back action; the QR and the seven words fill the window.
- T06 (covers R6): `s050_t06_r06_locked_page`: mounting the app, focusing it and receiving `locked` never call `unlock`; a click does, once; each error shows its text.
- T07 (covers R7): `s050_t07_r07_pending_dialog`: while `export_file` is pending the text shows and a second dialog command is refused by the page; `Suppressed { retry_after_ms: 1 200 }` shows "Try again in 2 s."
- T08 (covers R8): `s050_t08_r08_keys`: Enter sends, Shift+Enter adds a line, Escape closes the card.
- T09 (covers R9): `s050_t09_r09_i18n`: a key missing from `ca.json`, or a placeholder renamed, fails; a `navigator.languages` of `["ca-ES"]` gives Catalan, `["de"]` English.
- T10 (covers R10): `s050_t10_r10_look`: the tokens give at least 4.5:1 for the primary and secondary text colours in both schemes; every icon button has an `aria-label`; the verified icon is an SVG element.
- T11 (covers R11): CI step `s050_t11_r11_desktop_ui_job`, which runs the commands of R11; `.github/CONTRIBUTING.md` lists them.
- T12 (covers R12): `s050_t12_r12_flows`: the three UI flows of R12 pass over the fake bridge.

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
