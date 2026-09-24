---
name: typescript-svelte
description: TypeScript, Svelte 5 and Tauri 2 standard for the desktop client in `clients/desktop/`. Use it whenever you create or edit a `.ts`, `.svelte` or `.svelte.ts` file, a Tauri command or capability, `tauri.conf.json`, Vite/ESLint/Prettier config or `package.json`, or when reviewing desktop code — including small component tweaks. It assumes you have read the `architecture` skill, whose §7 "Client shape" holds everything the three clients share; this skill adds only the desktop mechanics, where the web view is the least trusted part and the Rust side of the Tauri process holds the socket, the store and the key.
---

# TypeScript / Svelte / Tauri standard

The shape of the app — layers, state and intents, how the core is driven, how
secrets are held, lifecycle, testing and tooling — is `architecture` §7. This
file is the desktop delta. The web view is a browser: keep it ignorant. Logic
that would also make sense on Android belongs in `core`; logic that touches a
key or a socket belongs in `src-tauri/` (the `rust` skill), never in the web
view.

## Language and toolchain

- TypeScript with `strict: true`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noImplicitOverride`. No `any`, no `as`
  casts except `as const`, no `!` non-null assertions, no `@ts-ignore`.
- Svelte 5 with **runes** (`$state`, `$derived`, `$effect`, `$props`); no
  legacy stores, no `export let`.
- Tauri 2. Vite. `pnpm` with a committed lockfile.
- No font or CDN dependency; everything ships in the bundle. Prefer the
  platform (`fetch`, `Intl`) and 40 lines of your own code over a package.

## Layout

```
src/lib/ui/         Svelte components
src/lib/state/      *.svelte.ts modules: one per screen, owns $state, send(intent)
src/lib/bridge/     typed wrappers around Tauri `invoke` and events; the only
                    place that knows command names
src-tauri/          Rust: Tauri commands → core::Session / Channel / Store,
                    keychain, socket. Follows the `rust` skill.
```

- State and intents are discriminated unions (`{ kind: 'loading' } | { kind:
  'locked' } | { kind: 'ready'; data } | { kind: 'failed'; error }`), held in a
  `.svelte.ts` module as `$state`; components receive them via `$props()`.
- **The bridge is the only caller of `invoke`.** Its argument and return
  types are **generated from Rust** (`tauri-specta` or equivalent), never
  hand-written twins that drift. Commands return `Result<T, E>` as a tagged
  union; `try/catch` is for IPC breakage only, mapped once to `failed`.

## Secrets in the web view

- The storage key, `K_ch`, `sk_u` and message keys **never** enter the web
  view. They live in `src-tauri/` as `Secret<N>`.
- The `.chatcfg` password is kept as `Uint8Array` (`TextEncoder`), passed once
  through `invoke`, then `.fill(0)`; it is never held as a `string` longer
  than the input element forces.
- The config QR is rendered from an image the Rust side produces; the
  password words are shown from a `Uint8Array` and zeroed on destroy.
- No `localStorage`, `sessionStorage`, `IndexedDB` or cookies. The web view
  runs with a temporary `data_directory` and no persistent cache
  (`docs/spec.md` §8 "Window and WebView"). Draft text is component state
  only.
- CSP in `tauri.conf.json` is strict: `default-src 'none'; script-src
  'self'; style-src 'self'; img-src 'self' asset:`. No inline scripts, no
  `eval`, no remote origins. Tauri capabilities grant only the commands the
  bridge uses.
- Window title is the app name only — never a channel or peer name (§8).

## TypeScript and Svelte idioms that carry a project rule

- Branded ids: `type PeerId = string & { readonly __brand: 'PeerId' }`; a
  `ServerId` cannot be passed where a `PeerId` is expected.
- Exhaustive `switch` over unions with an `assertNever(x)` default: adding a
  variant must break compilation everywhere it matters.
- `readonly` and `ReadonlyArray<T>` in props; `type` aliases and unions over
  `interface` hierarchies and classes.
- Components ≤ ~150 lines including markup and style. `$derived` for anything
  computable from state; `$effect` only for real side effects, with cleanup.
- `{#each messages as m (m.serverId)}`; never sort or filter in markup.
- Styles scoped in the component, one global file of CSS custom properties.
  No CSS framework, no runtime CSS-in-JS.
- Semantic elements, `aria-label` on icon buttons, visible focus, keyboard
  navigation for every action, `prefers-reduced-motion` and
  `prefers-color-scheme` respected. Strings via a tiny `t()` over JSON message
  files.

## Tauri side (`src-tauri/`)

Follows the `rust` skill. Additionally:

- Commands are thin: deserialise arguments, call `core`, serialise `Result`.
- `Session` runs in one `tokio` task per server with bounded channels; events
  reach the web view with `emit`. The socket is closed and the key zeroed on
  lock or when the window loses focus past `lock_timeout` (§8).
- The storage key is read from the OS keychain (`keyring` crate, one type
  `StorageKey`), never written to disk, never sent to the web view.

## Testing

- Vitest for state modules; fake the bridge with an in-memory implementation
  of its typed interface. `@testing-library/svelte` for the two UI flows of
  `architecture` §7.
- Test names: `test('s050_t02_r03 lock closes session and zeroes password
  buffer', …)`.
- No test touches Tauri IPC.

## Tooling

- ESLint (typescript-eslint strict + svelte plugin), Prettier, `pnpm check`
  (`svelte-check` + `tsc --noEmit`) and `pnpm test` clean before every commit
  and in CI. No `eslint-disable` without a reason comment.
- Reproducible builds: locked `pnpm-lock.yaml`, pinned Node in `.nvmrc`, no
  postinstall scripts that fetch, Tauri bundler with deterministic settings.
  Release signatures and notarisation happen in CI with offline keys.
