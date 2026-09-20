---
name: typescript-svelte
description: TypeScript, Svelte 5 and Tauri 2 standard for the desktop client in `clients/desktop/`. Use it whenever you create or edit a `.ts`, `.svelte` or `.svelte.ts` file, a Tauri command or capability, `tauri.conf.json`, Vite/ESLint/Prettier config or `package.json`, or when reviewing desktop code — including small component tweaks. It assumes you have read the `architecture` skill: the desktop UI is a thin shell over the Rust core linked directly into the Tauri process; the web view holds no protocol logic, no crypto and no secrets.
---

# TypeScript / Svelte / Tauri standard

The desktop app is Svelte pixels in a Tauri web view, talking to the Rust core
through typed commands. The Rust side of the Tauri process (`src-tauri/`) owns
the socket, the store and the key; the web view renders and sends intents. If
you are writing logic in TypeScript that would also make sense on Android, it
belongs in `core` (architecture §1); if it would only make sense on desktop
but touches a key or a socket, it belongs in `src-tauri/` (Rust skill), not in
the web view.

## Language and toolchain

- TypeScript with `strict: true`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noImplicitOverride`. No `any`, no `as`
  casts except `as const`, no `!` non-null assertions, no `@ts-ignore`.
- Svelte 5 with **runes** (`$state`, `$derived`, `$effect`, `$props`); no
  legacy stores, no `export let`.
- Tauri 2. Vite. `pnpm` with a committed lockfile.
- ESLint (typescript-eslint strict + svelte plugin) and Prettier run in CI and
  must be clean. No `eslint-disable` without a reason comment.
- No analytics, telemetry, error-reporting or font/CDN dependencies of any
  kind; everything ships in the bundle (`docs/spec.md` §8 "Telemetry").
  Every npm dependency has a one-line justification in the PR; prefer the
  platform (`fetch`, `crypto.getRandomValues`, `Intl`) and 40 lines of your
  own code over a package.

## Architecture inside the app

```
src/lib/ui/         Svelte components. Render state, emit intents. No logic.
src/lib/state/      *.svelte.ts modules: one per screen, owns $state, handles intents.
src/lib/bridge/     Typed wrappers around Tauri `invoke` and events. The only
                    place that knows command names.
src-tauri/          Rust: Tauri commands → core::Session / Channel / Store, keychain,
                    socket. Follows the `rust` skill.
```

- **State is one discriminated union per screen**
  (`type ChannelState = { kind: 'loading' } | { kind: 'locked' } | { kind:
  'ready'; data: ChannelData } | { kind: 'failed'; error: ErrorKind }`), held
  in a `.svelte.ts` module as `$state`. Components receive it via `$props()`
  and call one `send(intent)`.
- **Intents are a discriminated union** too. One `send()` per screen module;
  every user action is greppable.
- **Components decide presentation, never trust.** Colour a retired peer grey;
  never compute whether a peer is retired — the core said so.
- **The bridge is the only caller of `invoke`.** It exposes typed functions
  (`sendText(channelId, text): Promise<Result<void, ErrorKind>>`) whose
  argument and return types are **generated from Rust** (`tauri-specta` or
  equivalent) — never hand-written twins of Rust types, which drift.
- **Errors as values across the bridge.** Commands return `Result<T, E>`
  serialised as a tagged union; the bridge never throws for expected
  failures. `try/catch` is for IPC breakage only, mapped once to `failed`.

## Secrets in the web view

The web view is the least trusted part of the desktop app: it is a browser.
Keep it ignorant.

- The storage key, `K_ch`, `sk_u` and message keys **never** enter the web
  view. They live in `src-tauri/` as `Secret<N>`.
- The `.chatcfg` passphrase is typed in a component, kept as `Uint8Array`
  (`TextEncoder`), passed once through `invoke`, then `.fill(0)`. A `string`
  cannot be zeroed; do not hold the passphrase as one longer than the input
  element forces.
- The config QR is rendered from an image the Rust side produces; the
  passphrase words are shown from a `Uint8Array` and zeroed on destroy.
- No `localStorage`, `sessionStorage`, `IndexedDB` or cookies. The web view
  runs with a temporary `data_directory` and no persistent cache
  (`docs/spec.md` §8 "Window and WebView"). Draft text is component state
  only.
- CSP in `tauri.conf.json` is strict: `default-src 'none'; script-src
  'self'; style-src 'self'; img-src 'self' asset:`. No inline scripts, no
  `eval`, no remote origins. Tauri capabilities grant only the commands the
  bridge uses.
- Window title is the app name only — never a channel or peer name (§8).

## Types and style

- `type` aliases and discriminated unions over `interface` hierarchies and
  `class`es. Classes only for the rare thing that owns a resource.
- `readonly` everywhere data is not meant to change; `ReadonlyArray<T>` in
  props.
- Branded ids: `type PeerId = string & { readonly __brand: 'PeerId' }` — a
  `ServerId` cannot be passed where a `PeerId` is expected.
- Exhaustive `switch` over unions with an `assertNever(x)` default. Adding a
  variant must break compilation everywhere it matters.
- Full English words; components are nouns in PascalCase (`ChannelScreen.svelte`,
  `PeerRow.svelte`); state modules `channel.svelte.ts`; intents `XxxIntent`.
  One component per file; helpers used by a single screen live beside it.
- Functions ≤ ~40 lines; a component ≤ ~150 lines including markup and style.

## Svelte specifics

- Components are stateless: `$props()` in, callbacks out. `$state` inside a
  component only for transient visual state (open/closed, hover, scroll).
- `$derived` for anything computable from state; never duplicate state.
  `$effect` only for real side effects (focus, scroll-into-view) and always
  with cleanup.
- `{#each messages as m (m.serverId)}` — keyed by stable id; never sort or
  filter in markup, the state module (fed by the core) already did.
- Styles scoped in the component; a small set of CSS custom properties in one
  global file for colours, spacing and type. No CSS framework, no runtime
  CSS-in-JS.
- Accessibility: semantic elements, `aria-label` on icon buttons, visible focus,
  keyboard navigation for every action, respects `prefers-reduced-motion` and
  `prefers-color-scheme`. Strings via a tiny `t()` over JSON message files
  (English default, Catalan); nothing inline.

## Tauri side (`src-tauri/`)

Follows the `rust` skill. Additionally:

- Commands are thin: deserialise arguments, call `core`, serialise `Result`.
  No logic in a command body beyond that.
- `Session` runs in one `tokio` task per server host with bounded channels;
  events are forwarded to the web view with `emit`, and the socket is closed
  and the key zeroed on lock or when the window loses focus past
  `lock_timeout`.
- The storage key is read from the OS keychain (`keyring` crate, one type
  `StorageKey`), never written to disk, never sent to the web view.
- One connection per server host, TLS 1.3, no session resumption,
  `User-Agent: privatechat/1`, 70 000-byte frame limit (§6 "Transport").

## Testing

- Vitest for state modules: send intents, assert the state sequence; fake the
  bridge with an in-memory implementation of its typed interface.
- `@testing-library/svelte` for the two flows that matter: import a config,
  verify a peer. Not every button.
- Test names carry the spec id where they cover a requirement:
  `test('s050_t02_r03 lock closes session and zeroes passphrase buffer', …)`.
- No test touches Tauri IPC, the network or the keychain.

## Tooling

- `pnpm lint`, `pnpm check` (`svelte-check` + `tsc --noEmit`), `pnpm test`
  clean before every commit and in CI.
- Reproducible builds: locked `pnpm-lock.yaml`, pinned Node in `.nvmrc`, no
  postinstall scripts that fetch, Tauri bundler with deterministic settings.
  Release signatures and notarisation happen in CI with offline keys.
