# 041 — Desktop bridge: the Rust side of the Tauri process

Status: draft
Phase: 4
Related ADRs: 0012, 0017, 0020, 0028, 0037, 0038, 0040
Depends on: 011-config-format, 020-store-files, 027-core-api, 028-session-sans-io, 030-ws-protocol, 033-rate-limit-quotas, 035-server-ops, 040-uniffi
Blocks: 050-desktop-mvp, 053-device-security, 054-qr-invite
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The desktop client links the core as a Rust crate, with no wasm (`docs/spec.md` §9). Its web view is a browser, the least trusted part of the process, so it holds no key, no socket and no file (typescript-svelte skill). This spec defines everything on the Rust side of the Tauri process:

- the separate Cargo workspace it lives in (ADR 0040);
- the commands and events that are all the web view can reach, with their types generated for TypeScript;
- the web view's hardening;
- the connection host, which opens the TLS and SOCKS5 sockets, drives `Device` as spec 027-core-api R11 and R12 require, and reconnects with backoff;
- the storage key in the operating system's keychain;
- the test that closes phase 4 on the desktop side: two copies of the host, with no window, exchange a message through a real server.

The human reviewer decided on 2026-09-26 that all of this belongs here and not in spec 050-desktop-mvp, which is left with the Svelte UI alone (`docs/audit-log.md`, "Phase 4 drafts", Q3). During audit L the reviewer also decided that certificates are checked with no network request of their own, that the Rust side draws the invitation QR so the channel key never enters the web view, that the WebSocket crate's own randomness and SHA-1 are allowed as named exceptions, and that erasing local data, changing the proxy and the destructive actions of spec 027-core-api need a native confirmation (`docs/audit-log.md`, "Audit L", L-Q1 to L-Q4 and L-Q6). In round 3 the reviewer decided that web permissions are denied per engine with no `unsafe`, and that every unlock after a lock asks for a native confirmation (L-Q7, L-Q8).

**In plain words.** On the desktop, the app is two parts in one process: a web page that draws the screens, and Rust code that does everything else. The web page can only ask for things by name ("send this text in this channel"). It never sees a key, a socket or a file, and it can load nothing from the internet. Even the invitation QR, which holds the channel key, is drawn by Rust as a picture the page can show but not read. The Rust part keeps the storage key in the system keychain, opens the encrypted connections to the servers (through Tor when a proxy is set), and tells the page what happened. Erasing data, changing the proxy or dropping it, and unlocking again after a lock, ask for confirmation in a system dialog that the page cannot fake. The phase closes when two copies of this Rust part, without any screen, exchange a message through a real server.

## Requirements

**The workspace**

- R1 `clients/desktop/src-tauri/` MUST be a Cargo workspace of its own (ADR 0040), with a committed `Cargo.lock`, whose one crate `privatechat-desktop` (`publish = false`) depends on `privatechat-core` and `privatechat-store` by path. The crate is a library, `privatechat_desktop`, which holds the host, with `main.rs` reduced to the Tauri builder, so that `tests/` can reach the host; the in-memory `KeyStore` is `pub` under a `test-support` feature that only the crate's own dev-dependency on itself enables. Its `[lints]` MUST hold the entries of the root `[workspace.lints]` with the same levels, plus `clippy::wildcard_enum_match_arm` and `clippy::match_wildcard_for_single_variants` at `deny`, and its `[profile.release]` MUST equal the root one (`overflow-checks = true`), since Cargo applies only the profile of the workspace being built. Its own `clippy.toml` MUST hold the root `disallowed-methods` except the clock, file and network entries that the host needs, each removal commented with its reason: clippy reads the nearest `clippy.toml`, and the root one would forbid the host's clock. Its `Cargo.lock` MUST pin the same `libsodium-sys-stable` version as the root `Cargo.lock`. The crate MUST contain no `unsafe` block of its own. `check_s041_t01_r01_desktop_workspace` in `scripts/doc_lint.py` MUST fail when an entry of the root lint table is missing or weaker there, when the release profiles differ, or when the two locks pin different `libsodium-sys-stable` versions.
- R2 `clients/desktop/deny.toml` MUST start from the root `deny.toml`, and differ from it only in these ways, each commented with its reason (measured on 2026-09-26 with `cargo deny check` over the dependency set of this spec):
  - `[graph] targets` set to the desktop triples: `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.
  - `[bans] allow-wildcard-paths = true`, for the path dependencies of R1.
  - These wrappers on entries of the root `[bans] deny` list:
    - `rustls` under `privatechat-desktop` and `tokio-rustls`, and `ring` under `rustls` and `rustls-webpki`: the TLS stack (ADR 0040);
    - `sha1` and `rand` under `tungstenite`; `rand_core` under `rand`, `chacha20` and `getrandom`; `chacha20` under `rand`. These serve the WebSocket accept key, and the handshake key and frame masks that RFC 6455 uses against proxy cache poisoning, never secrecy (ADR 0040);
    - `getrandom` under `ring`, `rand`, `tauri` (its CSP nonces), `uuid`, `tempfile` and `secret-service`;
    - `sha2` under `tauri-codegen` (the CSP hashes, at build time) and `secret-service`; `aes` and `hkdf` under `secret-service`; `hmac` under `hkdf`. These are the session encryption of the Linux Secret Service;
    - `miniz_oxide` under `png` and `flate2`, and `flate2` under `png`: the menu icons (at run time) and the build-time icons;
    - `fastrand` under `phf_generator`, `async-executor`, `futures-lite` and `piper`.
  - Three entries that the root list does not have: `{ crate = "png", wrappers = ["muda", "tauri-codegen", "ico"] }`, and `native-tls` and `webpki-roots` with no wrapper.
  - `[advisories] ignore` naming these advisories, each for an unmaintained crate that the Tauri stack brings, with no vulnerability: RUSTSEC-2024-0436 (`paste`, under `specta`), RUSTSEC-2024-0370 (`proc-macro-error`, under the GTK crates), and RUSTSEC-2025-0075, -0080, -0081, -0098 and -0100 (the `unic-*` crates, under `urlpattern` and `tauri-utils`).
  - One `[[bans.build.bypass]]` for `webview2-com-sys` with `allow-globs = ["*/WebView2Loader.dll"]`, the loader that Microsoft ships.
  `aws-lc-rs`, `aws-lc-sys`, `openssl`, `openssl-sys`, `native-tls`, `webpki-roots`, `brotli` and `brotli-decompressor` MUST stay banned with no wrapper, so `tauri` MUST be built with `default-features = false` and without its `compression` feature. Any other difference amends this spec. `check_s041_t02_r02_desktop_bans` in `scripts/doc_lint.py` MUST fail on any difference from the root file other than those listed, and `cargo deny check` in `clients/desktop/src-tauri/` MUST be green.
- R3 In the pull request that marks this spec `accepted`:
  - AGENTS 2 MUST name the desktop workspace, with the TLS stack and the wrappers of R2, as its second exception;
  - AGENTS 24 MUST name the PNG decoder under `muda`, which never sees protocol data, and AGENTS 11 MUST cite §12 for the UI languages;
  - `docs/spec.md` §9 MUST name the desktop TLS stack in the desktop row (ADR 0040);
  - `docs/spec.md` §8 "Window and WebView" MUST name the incognito window and the temporary web view directory of R8, and §8 "Backup exclusion" MUST name the attribute of R15 for the desktop;
  - the typescript-svelte skill MUST describe the Rust side as this spec does: commands → `Host` → `Device`; one task per plan; generated types not committed, with hand-written wrappers only for the raw commands of R6; the CSP of R8; and the config QR as an image from the `qr` scheme.

**What the web view can reach**

- R4 The web view MUST reach the core only through the Tauri commands of `src-tauri/src/commands.rs`. There MUST be exactly one command for each of `unlock`, `lock`, `reset_local_data`, `status`, `acknowledge_settings`, `remove_broken`, `channels`, `create_channel`, `probe_server`, `import_qr`, `choose_chatcfg`, `import_file`, `export_qr`, `export_file`, `rename_channel`, `leave`, `send`, `messages`, `channel_status`, `gaps`, `peers`, `label`, `verify`, `verify_scanned`, `mute`, `fingerprint`, `own_fingerprint`, `retire`, `regenerate_identity`, `own_old_keys`, `forget`, `settings`, `set_default_server_url`, `set_lock_timeout_seconds` and `set_socks5_proxy`. `unlock`, `lock`, `reset_local_data`, `probe_server` and `choose_chatcfg` are the host's own (R6, R14, R16, R17). Every other command MUST call the `Device` method of the same name through the host (R10) and return its result, in the shape R6 and R7 give to `import_qr`, `import_file`, `export_qr`, `export_file`, `send` and `regenerate_identity`. `connections`, `probe_plan`, `on_connect`, `on_frame`, `on_tick`, `outgoing`, `on_disconnect`, `flush` and `purge_expired` MUST NOT be commands: the host alone calls them. No command takes `now`. The host reads the system clock in milliseconds since the Unix epoch, which is allowed here because this crate is not `core` (AGENTS 10). Every command that can open a dialog (R6, R16) MUST be `async`, since Tauri runs a synchronous command on the main thread and a blocking dialog there freezes the app.
- R5 The argument and result types of every command other than those of R6 MUST be generated by `tauri-specta` and `specta`, both pinned exactly at a `2.0.0-rc` release (no stable release for Tauri 2 exists, measured on 2026-09-26). They are generated into `clients/desktop/src/lib/bridge/generated.ts` by the test `export_bindings` and before every web build. That file MUST NOT be committed (AGENTS 16), and `.gitignore` MUST list it with Tauri's `src-tauri/gen/`. The core carries no `serde` and no `specta`, so `src-tauri/src/wire.rs` defines one mirror type for each crossing type, with one `From` each. The types cross as follows:
  - Ids cross as lowercase hexadecimal strings: `channel_id`, `server_id` and `ClientRef` as 32 characters, `PeerId` as 64. On the TypeScript side each is a branded type (`ChannelId`, `ServerId`, `ClientRef`, `PeerId`). An incoming id that is not exactly that returns `BadLength` before any `Device` call.
  - A `u64` crosses through the newtype `JsU64`, whose `Serialize` saturates at 2^53 − 1 and which is declared to specta as `number`, so that a time from an untrusted server that is too large to represent keeps its order and never wraps around (specta refuses a bare `u64`).
  - The `qr` of a `Fingerprint` crosses as a string: it is the ASCII text of a public key, not a secret.
  - Errors cross as the tagged union of `Error`, with `Store` carrying its reason, plus `Locked` (the device is locked), `KeyLost`, `KeychainUnavailable`, `AlreadyRunning` (R15), `Cancelled` (a dialog was dismissed or declined, another confirmation is open, or no file is pending), `Suppressed { retry_after_ms }` (a confirmation of that kind was declined less than 60 000 ms ago, R9) and `FileIo` (a file or directory could not be read, written or deleted).
- R6 Secrets and files cross as follows:
  - The QR text of `import_qr` and the `.chatcfg` password of `import_file` MUST reach their command as the raw IPC body (`tauri::ipc::Request` with `InvokeBody::Raw`), never as JSON. A body that is not raw returns `BadPayload`. Neither command takes `replace_broken`: the host first calls the `Device` with `replace_broken = false`, and only when that returns `Store(Corrupt)` or `Store(UnsupportedVersion)` does it ask the confirmation of R16 and call again with `true`. It claims the dialog slot of R9 first, and only then keeps, in one host-owned `Zeroizing` slot, its copy of the body and, for `import_file`, its own copy of the pending file's bytes; the second call uses exactly those. The slot is emptied after the second call, on a decline, `Suppressed` or `Cancelled`, and by `lock`; a yes that finds the generation changed returns `Locked`. The re-check of R9 for this confirmation is the generation alone: the core's second call checks the entry itself. The command copies the body into a `Zeroizing<Vec<u8>>` and never into a `String` or a log. Tauri's own request buffer is freed without being zeroed, a residual of `docs/spec.md` §8 "FFI boundary".
  - `choose_chatcfg` MUST open the native open dialog from the Rust side and accept only a regular file: a path that is not one, checked with `symlink_metadata` before it is opened (so that a FIFO is never opened), returns `FileIo`. It reads at most 1 086 bytes of it. A file longer than 1 085 bytes (spec 011-config-format T13) returns `BadConfig` with nothing more read. The host keeps the bytes as the one pending file until an `import_file` returns `Ok`, `lock` runs, or another `choose_chatcfg` replaces it. `import_file` uses the pending file, and returns `Cancelled` when there is none.
  - `export_file` MUST first open the native save dialog from the Rust side, and return `Cancelled` with no `Device` call when it is dismissed. It then calls `Device::export_file` and writes the file to the chosen path. When that write fails, it returns `FileIo` and no password. Otherwise it returns the seven-word password as a raw binary response (`tauri::ipc::Response`), never as a JSON string.
  - `export_qr` MUST render the config QR from `Device::export_qr` as an SVG image on the Rust side, with the `qrcode` crate and no default feature. The text and the SVG are held in `Zeroizing` buffers. The image is served on the custom URI scheme `qr` (`qr://localhost/<n>`, and `http://qr.localhost/<n>` on Windows), where `<n>` is a counter, with `Cache-Control: no-store` and no CORS header. `export_qr` returns only that URL. The URL answers until the next `export_qr`, a `leave` of that channel, or `lock`. The page can show the image, but no script can read its pixels (a cross-origin image taints a canvas, measured in WKWebView on 2026-09-26) or fetch it (R8's `connect-src`). The text never enters the web view.
  - The open and save dialogs are opened from Rust with `tauri-plugin-dialog`, through `Dialogs` inside `spawn_blocking` (R9), so that the bytes of a `.chatcfg` file never enter the web view.
  - Each of these commands is registered outside `tauri-specta`, through one handler that routes their names first, with a hand-written wrapper in `src/lib/bridge/raw.ts`.
- R7 The host MUST take the events out of every `Device` result that carries them: `on_frame`, `on_tick`, the `events` of `Sent`, and the result of `regenerate_identity`. It acts on `Reconnect`, `ServerFull` and `UnsupportedServer` as R13 says, and emits every other event to the web view as `core-event`: a tagged union of the `Event` variants of spec 028-session-sans-io that name a channel (`Subscribed`, `HistoryTruncated`, `Message`, `Delivered`, `NotDelivered`, `StatusChanged`, `StorageFailed`, `SubscribeRefused`, `ChannelFull`), typed by R5. `send` therefore returns `Sent` without `events`, and `regenerate_identity` returns nothing. The host MUST also emit `connection-state { channels, state }` for the channels of a plan whenever their state changes, with `state` one of:
  - `connecting`, from the start of the connect;
  - `connected`, from `on_connect`;
  - `retrying`, while a closed socket waits out its backoff;
  - `server_full`, for 60 000 ms after `ServerFull`, then `connected` again;
  - `unsupported_server`, until the next `unlock` or a new plan `id`;
  - `proxy_refused`, until `set_socks5_proxy` returns `Ok`.
  It MUST emit `locked` when the device locks. A channel that needs a proxy is in no plan (spec 027-core-api R10), and the UI reads it from `ChannelInfo::needs_proxy`.
- R8 `tauri.conf.json` MUST set the content security policy `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' qr: http://qr.localhost; connect-src ipc: http://ipc.localhost; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`, with no remote origin. `connect-src` names Tauri's IPC scheme so that invokes never fall back to its JSON `postMessage` path. It MUST also set:
  - no `withGlobalTauri`;
  - no developer tools in release builds;
  - `app.security.assetProtocol.enable = false`;
  - a `Permissions-Policy` header, through `app.security.headers`, that denies camera, microphone, display capture, clipboard read, geolocation and every other powerful feature. This is the defence on WebView2, which is Chromium; WKWebView and WebKitGTK ignore the header (measured on 2026-09-26).
  Web permission requests MUST be denied on each engine with no `unsafe` (decided with the human reviewer, `docs/audit-log.md`, "Audit L", L-Q7): on Linux, a WebKitGTK `permission-request` handler, reached through `with_webview`, that denies every request; on macOS, an app bundle that names no `NS*UsageDescription` key at all and no camera or microphone entitlement, so that the system denies them (measured: `navigator.mediaDevices` is absent, and a clipboard read without a user gesture is refused); on Windows, the header above, and the app never calls `enable_clipboard_access`. WebView2 may still show its own prompt for a request the header does not cover, a documented residual. At start, before the window is created, the app MUST refuse to open a window when any `WEBVIEW2_*` or `WEBKIT_INSPECTOR*` variable is set in its environment, since those can turn on remote debugging or a persistent profile. The refusal covers the environment only: the WebView2 registry policies and a per-app `defaults` key that turn on the WebKit developer extras need the same user or an administrator, which are out of the model of `docs/spec.md` §8. The first line of `main` installs the panic hook of R10, and no `tracing` or `log` subscriber, and no logging plugin, is ever installed. `build.rs` MUST declare the commands of R4 through `tauri_build::AppManifest::commands`, since without an app manifest Tauri allows every registered command whatever the capabilities say. The capability file MUST grant, to the window `main` and to local origins only, exactly the permissions of those commands and `core:event:allow-listen`, with no dialog permission and no `core:default`. The one window MUST be created `incognito`, with its web view data directory in a new temporary directory (used as the WebView2 user data folder on Windows; WKWebView and WebKitGTK keep nothing on disk when incognito). The app deletes that directory, best effort, when it quits, and deletes any leftover one at the next start, only while it holds `instance.lock` (R15) and never the directory of its current window. The window's navigation handler MUST refuse every URL outside the app's own origin, and it MUST refuse new windows. Its title MUST be the app name, and nothing changes it (`docs/spec.md` §8 "Window and WebView").

**The connection host**

- R9 The host MUST NOT depend on the Tauri runtime. It emits through a trait `Sink`, and opens dialogs through a trait `Dialogs` (open, save, confirm), always inside `spawn_blocking`. The app implements both over Tauri's `emit` and `tauri-plugin-dialog`, and the tests over channels and fixed answers, so that the exit test (R18) runs the host without a window. A confirmation MUST:
  - be a native dialog built with `rfd` directly (pinned, `default-features = false`, features `gtk3` and `common-controls-v6`, so that zenity never runs), with no parent and `rfd::MessageButtons::OkCancelCustom(<safe label>, <action label>)`, so that the safe button comes first and is the default on macOS and Windows. On macOS and Windows it is an `rfd::AsyncMessageDialog` awaited on a `tokio` task; on Linux it is the synchronous `MessageDialog::show` inside `spawn_blocking`. It never runs on, or blocks, the main thread (measured on 2026-09-26: a synchronous dialog run from the main thread stops the event loop on macOS, so no event, not even `locked`, and no close request is handled while it is open). Only rfd's own `Custom(<action label>)` accepts: a dismissal (Esc, the close button) is rfd's `Cancel` on every backend, and any other answer is a decline. `tauri-plugin-dialog`'s message dialog MUST NOT be used for a confirmation, since it maps a dismissal to the second label (measured on 2026-09-26);
  - treat an accept that returns less than 1 000 ms after the dialog was shown as a decline, so that a click the page timed to land on the dialog's button is not a yes (the input protection of browsers' permission prompts), and return `Cancelled` with no dialog while the main window is not focused;
  - word its action button by kind and, for a proxy, by class ("Erase all data", "Use a proxy on another computer", "Use no proxy", "Unlock"), so that a dialog the page substituted for the one the user expected does not show the button they expect;
  - take its text from the string resources of `src-tauri/strings/`, embedded at build time, with English as the source and the UI languages of `docs/spec.md` §12, in the locale of the operating system, never one the web view names (AGENTS 11). A missing key falls back to English. In every locale the action labels differ from each other and from the safe label, no label holds `&` or `_` (access keys on Windows and GTK), and every template keeps the placeholders of the English one;
  - be one at a time, sharing one slot with the open and save dialogs of R6: a request while one is open returns `Cancelled`. After any dialog closes, no dialog of any kind opens for 3 000 ms (`Suppressed`), so that a close or quit click can land between dialogs a script chains;
  - after the user declines, return `Suppressed` with no dialog for the same kind of confirmation for 60 000 ms, so that a script cannot repeat a dialog until it is accepted, and the UI can say why nothing happened;
  - show only text that the host composed. A proxy is checked against the grammar of `set_socks5_proxy` before its dialog, and shown as host and port, described as "on this device" only for a loopback IP literal (spec 027-core-api R10) and as "on another computer" otherwise. A broken entry is first looked up in `status().broken`, and an unknown name returns `UnknownChannel` with no dialog; it is shown by its `channel_name` when it has one, and otherwise as "an unreadable channel", with the text of spec 027-core-api R3 for its reason (for `UnsupportedVersion`, "written by a newer version of the app: update it, or remove the channel and lose its local history");
  - run with no lock held, neither the `Device`'s nor the mutex of R15, and never count as a call in flight for R17. The host records the generation before the dialog; after a yes it takes the lock again, returns `Locked` when the generation changed, and checks again that the target still stands before the call: for `RemoveBroken`, the name is still in `broken`, otherwise `UnknownChannel`; for `AcknowledgeSettings`, `settings_reset` is still set, otherwise `Ok` with no call; for `ReplaceNewerSettings`, `settings_reason` is still `Some(UnsupportedVersion)`, otherwise the call goes on with `replace_newer = false`; for `SetProxy` and `ReplaceBroken`, the generation alone. `unlock` and `reset_local_data` follow R15 instead. `lock` never waits on a dialog.
  While the device is locked, every command other than `unlock`, `lock` and `reset_local_data` returns `Locked` before any dialog.
- R10 The host MUST hold the `Device` in a `Mutex<Option<Device>>`, with an unlock generation that every `unlock` and every `lock` increases, and run every `Device` call inside `tokio::task::spawn_blocking`. In the same hold of the lock, after `open` and after each call that spec 027-core-api R11 names, it MUST:
  - take the events out as R7 says;
  - reconcile its sockets with `connections()`: one `tokio` task per plan `id`, tagged with the generation, started for each new `id` and cancelled when its `id` leaves the plan;
  - push `outgoing()` of every connected plan onto that plan's ordered writer queue, which holds at most 256 frames.
  Only the plan's task writes to its socket, in queue order, so that frames drained by different calls never reorder. Each queued frame carries the generation and the number of the socket it was drained for. The queue is emptied in the same hold of the lock as `on_disconnect`, and the task drops any frame whose socket number is not the current one's, so that no frame drained for one socket is ever written on the next. A full queue closes the socket. No command waits on a network write. A frame or an event that carries an older generation MUST be dropped, and every blocking closure records the generation it was started under and, once it holds the lock, returns `Locked` without touching the `Device` when the generation changed. A plan task that ends with a panic MUST be handled as a closed socket (`on_disconnect`, then R13's backoff), its payload dropped. A panic inside a call MUST return `Core(Internal)` without its payload, a poisoned lock MUST make every later call return `Core(Internal)`, and the first hold that finds it poisoned makes the host start the lock routine itself, which emits `locked`; the routine drops a poisoned `Device` without `flush` (the state of a call that panicked half-way is not written), clears the poison (`Mutex::clear_poison`), and the next `unlock` starts clean, and the release build installs a panic hook that writes nothing.
- R11 While the device is unlocked, the host MUST call `on_tick(now)` every 1 000 ms, the first 1 000 ms after `unlock`, on a `tokio` interval with `MissedTickBehavior::Delay`. It then handles the events by R7 and reconciles and drains by R10, in the same hold of the lock.
- R12 For each plan, the task MUST open the socket along its `Route`:
  - Proxy: with `socks5_proxy` set, through the client of `src-tauri/src/socks5.rs`. It sends a SOCKS5 `CONNECT` (RFC 1928) with the host as a domain name (`ATYP` 3), so that no host name is ever resolved on this device. It offers only username and password authentication (RFC 1929), with `socks_username` and an empty password. A reply `VER` other than 5, a selected method other than `0x02`, a sub-negotiation `VER` other than 1, or an authentication status other than `0x00` is `proxy_refused` (R13). A `CONNECT` reply other than `0x00`, or an unknown `ATYP` in it, closes the socket. The reply's bound address is read at exactly its declared length. Without a proxy, it opens a TCP connection to `host:port`.
  - TLS: when `tls` is true, TLS 1.3 only, through `rustls` with the `ring` provider (`default-features = false`, features `ring` and `std`, and `tokio-rustls` likewise), `Resumption::disabled()`, and SNI set to `host`. Certificates MUST be checked by `rustls`'s `WebPkiServerVerifier` over the roots that `rustls-native-certs` reads from the operating system's trust store at `unlock`, with no revocation list and no revocation fetch. The TLS stack makes no network request of its own. There is no pinning and no way to skip the check.
  - WebSocket: `tokio-tungstenite` with `default-features = false` and the `handshake` feature, driven by `client_async_with_config` over that stream. It performs the handshake of `GET /` (spec 030-ws-protocol R3), sending exactly the headers of `docs/spec.md` §6 "Transport" with `User-Agent: privatechat/1`, no `Origin` header and no extension. The maximum frame and message size is 70 000 bytes (spec 030-ws-protocol R4). A text frame closes the socket.
  - Timeouts: from the start of the connect to the end of the WebSocket handshake, 30 000 ms, or 60 000 ms through a proxy to a `.onion` host (an onion rendezvous often takes longer than 30 s). A write pending for 30 000 ms closes the socket. After the handshake, 75 000 ms with no frame of any kind received (the server pings every 30 000 ms, spec 033-rate-limit-quotas R4) closes it.
  - Once open, it calls `on_connect(id, now)`, passes every binary frame to `on_frame`, and calls `on_disconnect(id)` when the socket closes, whoever closed it.
- R13 A socket that closes for any reason other than the stop rules below and `lock` MUST be reopened while its `id` is in the plan, after 1 000 ms, then 2 000 ms, doubling up to 60 000 ms. The delay resets once a connection has stayed open for 60 000 ms. The host acts on these events and states:
  - After `Event::UnsupportedServer`, it MUST close that socket and not reopen it until the next `unlock` or a new plan `id`.
  - After `Event::Reconnect`, it MUST close the socket of the connection it names and reopen it with the backoff (spec 027-core-api R11).
  - After `Event::ServerFull`, it keeps the socket open (spec 028-session-sans-io R16 pauses publishing).
  - After `proxy_refused`, it closes the socket and does not reopen it until `set_socks5_proxy` returns `Ok`.
- R14 `probe_server(url)` MUST call `probe_plan(url)`, and return `NotYet` for `None` and the error for `Err`. Otherwise it MUST open a socket along the route as R12 does, with R12's connect bound, and pass the first binary frame received within 30 000 ms after the handshake to `probe_hello`. It then closes the socket. The result is:
  - `Supported` for `Ok(true)` and `Unsupported` for `Ok(false)`;
  - `ProxyRefused` for the proxy failures of R12;
  - `Unreachable` for `BadPayload`, for a socket that fails, and when no frame arrives in time (spec 027-core-api R12).
  A probe is never a planned connection, and one probe runs at a time: a second `probe_server` waits for the first.

**The storage key and the lock**

- R15 The data directory MUST be `app_local_data_dir()/data`: Application Support on macOS, `%LOCALAPPDATA%` on Windows (never the roaming profile, which syncs), `$XDG_DATA_HOME` on Linux. It is created with mode 0700 on Unix, and on macOS it carries the backup exclusion attribute `com.apple.metadata:com_apple_backup_excludeItem` with the value that `tmutil addexclusion` writes (the binary property list of the string `com.apple.backupd`), set through the `xattr` crate, a macOS-only dependency, so that Time Machine keeps no history past its TTL (`docs/spec.md` §8 "Backup exclusion"). It is separate from the web view's temporary directory. The data directory "holds data" when `settings.bin` exists or `channels/` holds a directory, read with `try_exists` and `read_dir`: only `NotFound` counts as absent, and any other error makes `unlock` and `reset_local_data` return `FileIo` and touch neither the keychain nor the directory. At start, before any keychain access, the app MUST take an exclusive lock (`File::try_lock`) on `app_local_data_dir()/instance.lock` and hold it for the life of the process. `WouldBlock` makes `unlock` and `reset_local_data` return `AlreadyRunning` and touch nothing, and any other error makes them return `FileIo`. While this process does not hold the lock, each `unlock` tries to take it again. `unlock`, `lock` and `reset_local_data` are serialised by one first-in, first-out `tokio::sync::Mutex`, which is never held across a dialog. `unlock` and `reset_local_data` ask their confirmation (R16) first; after a yes they take the mutex and check again: `unlock` returns `Ok` when the device is already unlocked, and `reset_local_data` goes on, since it is valid locked or unlocked. An `unlock` records, when it is called, how many times this process has opened a `Device`; when that count changed before it holds the mutex and it asked no confirmation, it returns `Cancelled`, so that an `unlock` queued before the first open never skips the confirmation after a lock. The steps of R17 are one internal routine that runs with the mutex held: `lock` takes the mutex and runs it, and `reset_local_data` runs it inside its own hold.
- R16 The storage key MUST live in the operating system's keychain through `keyring` 4, with the native store of each system (the macOS Keychain; the Windows Credential Manager; the Secret Service over D-Bus on Linux). It is one entry whose service is the app identifier constant and whose user is `storage-key:` followed by the canonical path of `app_local_data_dir()` (`fs::canonicalize`; the app creates that directory at start for `instance.lock`) and `/data`, so that it can be named whether the data directory exists or not, so that an install at another path (another packaging, another `$XDG_DATA_HOME`, a development build) never reads or deletes this one's key, and two spellings of one directory reach the same entry. On Windows a user longer than 513 characters (`CRED_MAX_USERNAME_LENGTH`) makes `unlock` return `FileIo`. The entry holds 32 bytes read and written with `get_secret` and `set_secret`, in `spawn_blocking`, and every read returns a `Zeroizing` buffer. The host calls `keyring::Entry::store_status()` once, before any entry is built, and maps its error to `KeychainUnavailable`. On Windows the entry MUST be built through `keyring-core` (pinned at the exact version that `keyring` locks) with `Entry::new_with_modifiers` and the persistence `Local` (`CRED_PERSIST_LOCAL_MACHINE`), so that it does not roam; keyring 4's own `Entry::new` passes no modifier and the Windows store defaults to `Enterprise`, which roams, while the other stores reject that modifier and use `keyring::Entry::new`. `unlock` while unlocked MUST return `Ok` without reopening, with no dialog and no suppression, before anything else. While this process has opened no `Device` yet, `unlock` opens with no dialog; once it has opened one, every later `unlock`, whatever locked the device (`lock`, a reset, spec 053-device-security), MUST first ask through a confirmation (R9), since reading the keychain asks the user for nothing and a script that outlived the lock could otherwise unlock at once (decided with the human reviewer, `docs/audit-log.md`, "Audit L", L-Q8). Otherwise `unlock` MUST behave as follows:
  - The entry reads as 32 bytes and the directory holds data: copy the bytes into a `[u8; 32]`, build the key with `StorageKey::from_bytes`, and open the device with `DataDir::open` and `Device::open`.
  - The directory holds no data and an entry exists: delete the entry and go on as for a first run, so that an entry planted before the first run is never used.
  - The directory holds no data and there is no entry: draw a new key with `generate_storage_key` (spec 040-uniffi R8), write it, and read it back. The read-back MUST return 32 bytes equal to the drawn key. Otherwise it zeroes the drawn array, deletes the entry (best effort), returns `KeychainUnavailable`, and opens nothing. When the read-back matches, the drawn array goes to `StorageKey::from_bytes` and the device opens.
  - The directory holds data and there is no entry, or the entry is not 32 bytes: return `KeyLost` and create nothing. No transient failure may ever draw a new key (`docs/spec.md` §8 "Loss of the wrapping key").
  - Any other keychain error: return `KeychainUnavailable` and create nothing.
  The following MUST ask through `Dialogs::confirm` and, when the user declines, return `Cancelled` with the `Device` and the files untouched (spec 027-core-api R2, R3 and R5, decided with the human reviewer, `docs/audit-log.md`, "Audit L", L-Q4 and L-Q6):
  - `reset_local_data`. It then locks when unlocked (R17), deletes the data directory, then (best effort) the web view's temporary directory, and only then the keychain entry. When the data directory cannot be fully deleted, it returns `FileIo` and keeps the entry. The next `unlock` then starts as a fresh install.
  - `set_socks5_proxy`, naming the new proxy or "no proxy".
  - `acknowledge_settings` while `settings_reset` is set, naming the proxy in memory, or "no proxy"; when `settings_reason` is `Io`, the text says that the stored settings are read again first and used if they now read.
  - `acknowledge_settings(true)` whenever `settings_reason` is `Some(UnsupportedVersion)`, with spec 027-core-api R2's text ("written by a newer version of the app: update it, or replace these settings") and the proxy in memory. When both bullets apply, this dialog alone is shown. The host passes `replace_newer = true` to the `Device` only after this dialog, and `false` otherwise, so that a re-read after `Io` that finds a newer file never replaces it behind the weaker dialog; the UI asks again once the reason reads `UnsupportedVersion`.
  - `remove_broken`, naming the entry as R9 says.
  - The second call of an import with `replace_broken` (R6), with fixed host text by the first call's reason: for `Corrupt`, "replace an unreadable channel on this device with this invitation, and lose what it held here"; for `UnsupportedVersion`, spec 027-core-api R3's text. The host cannot name the entry, since only the core can read the invitation's `channel_id`.
  - `unlock` after a `lock`, as above.
  The key never leaves the Rust side.
- R17 The lock routine (R15) MUST, in this order:
  - increase the generation under the lock, so that no reconcile, tick or queued closure after that point starts a task or touches the `Device`;
  - wait for any `Device` call in flight, with the lock released;
  - stop the tick;
  - abort every plan task and wait for each to end, with the lock released, then call `on_disconnect` for each plan that was connected, in one hold of the lock, recovering a poisoned lock;
  - call `Device::flush(now)`, and drop the `Device` whatever `flush` returned, recovering a poisoned lock to reach it;
  - drop the pending file, the kept import slot and the QR image (R6);
  - emit `locked` last.
  No `Sink` call follows `locked` until the next `unlock` returns `Ok`. After that, every command other than `unlock`, `reset_local_data` and `lock` returns `Locked`. Closing the window or quitting the app MUST lock first:
  - The app refuses a close or exit request (`prevent_close`, `RunEvent::ExitRequested` with `prevent_exit`) while a process-wide `AtomicBool` "quitting" is clear, sets it, and from then on every dialog request and every `unlock` returns `Cancelled`.
  - An async task takes the mutex of R15, runs the lock routine, and calls `exit(0)` without releasing the mutex, so that no `unlock` or reset answered after it runs; an `ExitRequested` or `CloseRequested` that finds the flag set goes through. The main thread never blocks on the host.
  - On macOS the app replaces the default menu, whose Quit item is `terminate:` and skips `ExitRequested`, with one whose Quit is a plain item with the accelerator `CmdOrCtrl+Q` that starts this path. A termination that bypasses it (the Dock's Quit, logout) reaches only `RunEvent::Exit`, where the host drops the `Device` synchronously, best effort, without `flush`: a documented residual. When the device locks on its own (session lock, timeout) is spec 053-device-security's.

**The exit test**

- R18 `clients/desktop/src-tauri/tests/phase4_exit.rs` MUST run two hosts, each over its own temporary data directory, an in-memory keychain store and `Dialogs` that confirm. They run against the `privatechat-server` binary of spec 035-server-ops, whose path the CI job passes in `DESKTOP_TEST_SERVER_BIN`. The test starts it with an empty environment (`env_clear`) plus exactly:
  - `PRIVATECHAT_LISTEN=127.0.0.1:0`;
  - `PRIVATECHAT_ONION_LISTEN=127.0.0.1:<p>`, where `<p>` is a port the test has just bound and released (035 requires an address other than the first, and macOS has no loopback address but 127.0.0.1 by default);
  - `PRIVATECHAT_URLS` naming the test's `ws://` onion URL;
  - `PRIVATECHAT_DB` in a temporary directory;
  - `PRIVATECHAT_LOG=info`.
  It reads the two bound ports from the fields `listen_port` and `onion_port` of the server's start line (spec 035-server-ops R4). A SOCKS5 proxy written for the test on `127.0.0.1` accepts only method `0x02`, and forwards every `CONNECT` for the onion host to the onion listener. Both hosts set `127.0.0.1:<proxy port>` as their SOCKS5 proxy. Host A creates a channel with `ws://<56 characters>.onion`, and host B imports the QR text that A's `Device::export_qr` returns, through the host's `import_qr`. Each sends one message. The test MUST end with:
  - each host having received the other's message as `core-event` `Message`, and its own as `Delivered`;
  - the proxy having seen a different `socks_username` for each plan;
  - the whole run taking at most 120 s of real time.
  The CI job `desktop` runs on Linux and macOS, and its Windows leg runs `cargo test` with T18 left out (`cfg(not(windows))`: the server stops on signals that Windows lacks). It MUST build the server from the root workspace and run this test, together with `cargo test`, clippy, rustfmt and `cargo deny check` in `clients/desktop/src-tauri/`, and the regeneration of R5. `.github/CONTRIBUTING.md` MUST list the same commands (AGENTS 17).

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Ids from the web view | exactly 32 or 64 lowercase hex characters | `BadLength`, no `Device` call |
| `u64` to the web view | 0..=2^53 − 1 | saturated at 2^53 − 1 |
| `.chatcfg` file from the dialog | a regular file | `FileIo`, never opened |
| `.chatcfg` size | ≤ 1 085 B | `BadConfig`, nothing more read |
| Connect and handshake | ≤ 30 000 ms; ≤ 60 000 ms through a proxy to `.onion` | socket closed, backoff |
| A pending write | ≤ 30 000 ms | socket closed, backoff |
| Silence on an open socket | ≤ 75 000 ms | socket closed, backoff |
| Writer queue per plan | ≤ 256 frames | socket closed, backoff |
| Backoff | 1 000 ms doubling to 60 000 ms, reset after 60 000 ms connected | — |
| Probe's first frame | ≤ 30 000 ms after the handshake | `Unreachable` |
| Tick | every 1 000 ms while unlocked, the first 1 000 ms after `unlock` | delayed, never burst |
| WebSocket frame and message | ≤ 70 000 B | socket closed |
| Keychain secret, when the directory holds data | exactly 32 bytes | `KeyLost` |
| Keychain user on Windows | ≤ 513 characters | `FileIo` |
| Dialogs | one at a time, file dialogs included; none for 3 000 ms after any closes; none of a kind for 60 000 ms after a decline; an accept within 1 000 ms of showing | `Cancelled`; `Suppressed`; a decline |
| Probes in flight | one | the next waits |
| SOCKS5 username | the 8 characters of the plan; password empty | — |

## Interface

```
clients/desktop/src-tauri/Cargo.toml           a workspace of its own, privatechat-desktop (R1)
clients/desktop/src-tauri/Cargo.lock
clients/desktop/src-tauri/clippy.toml          R1
clients/desktop/deny.toml                      R2
clients/desktop/src-tauri/build.rs             AppManifest::commands (R8)
clients/desktop/src-tauri/tauri.conf.json      R8
clients/desktop/src-tauri/capabilities/main.json
clients/desktop/src-tauri/src/lib.rs           privatechat_desktop: the modules below
clients/desktop/src-tauri/src/main.rs          the Tauri builder, the window, Sink and Dialogs over Tauri, the qr scheme
clients/desktop/src-tauri/src/commands.rs      R4–R6
clients/desktop/src-tauri/src/wire.rs          the mirror types and JsU64 (R5)
clients/desktop/src-tauri/src/host.rs          Host, Sink, Dialogs, the tick, reconcile, the writer queues (R9–R11, R13, R17)
clients/desktop/src-tauri/src/socket.rs        TCP, TLS and WebSocket per route (R12), the probe (R14)
clients/desktop/src-tauri/src/socks5.rs        R12
clients/desktop/src-tauri/src/key.rs           the instance lock, the keychain entry and unlock (R15, R16)
clients/desktop/src-tauri/src/confirm.rs       the rfd confirmations (R9)
clients/desktop/src-tauri/strings/             the dialog texts, English source and the UI languages (R9)
clients/desktop/src-tauri/tests/phase4_exit.rs R18
clients/desktop/src/lib/bridge/generated.ts    R5, generated, not committed
clients/desktop/src/lib/bridge/raw.ts          the wrappers of the raw commands (R6)
```

```rust
pub trait Sink: Send + Sync + 'static {
    fn core_event(&self, event: BridgeEvent);
    fn connection_state(&self, channels: Vec<ChannelIdHex>, state: ConnectionState);
    fn locked(&self);
}
pub trait Dialogs: Send + Sync + 'static {   // blocking; the host calls them inside spawn_blocking
    fn open_file(&self) -> Option<PathBuf>;
    fn save_file(&self) -> Option<PathBuf>;
    fn confirm(&self, what: &Confirmation) -> bool;
}
// BridgeEvent: the tagged union of R7; SentView: Sent without events; ChannelIdHex: a 32-character lowercase hex id (R5);
// ProxyShown: a proxy checked against the grammar, split into host and port, with whether it is a loopback IP literal (R9)
pub struct HostPaths { pub data_dir: PathBuf, pub webview_dir: PathBuf, pub instance_lock: PathBuf }
pub struct Host { /* Mutex<Option<Device>>, the generation, the plan tasks and their queues, the tick, the pending file, the QR image, Sink, Dialogs */ }
impl Host {
    pub fn new(paths: HostPaths, keychain: Box<dyn KeyStore>, sink: Arc<dyn Sink>, dialogs: Arc<dyn Dialogs>) -> Host;
    pub async fn unlock(&self) -> Result<(), BridgeError>;
    pub async fn lock(&self);
    pub async fn reset_local_data(&self) -> Result<(), BridgeError>;
    // the calls with no confirmation, no file and no events to take out; spawn_blocking, then reconcile and drain
    pub async fn call<T: Send + 'static>(&self, f: impl FnOnce(&mut Device, u64) -> Result<T, Error> + Send + 'static) -> Result<T, BridgeError>;
    pub async fn send(&self, channel: [u8; 16], body: String, display_name: Option<String>) -> Result<SentView, BridgeError>;   // events taken out (R7)
    pub async fn regenerate_identity(&self, channel: [u8; 16]) -> Result<(), BridgeError>;                                       // events taken out (R7)
    pub async fn import_qr(&self, text: Zeroizing<Vec<u8>>) -> Result<Imported, BridgeError>;          // replace_broken asked by R6 and R16
    pub async fn choose_chatcfg(&self) -> Result<(), BridgeError>;
    pub async fn import_file(&self, password: Zeroizing<Vec<u8>>) -> Result<Imported, BridgeError>;
    pub async fn export_qr(&self, channel: [u8; 16]) -> Result<String, BridgeError>;                 // the qr: URL
    pub async fn export_file(&self, channel: [u8; 16]) -> Result<Zeroizing<Vec<u8>>, BridgeError>;   // the password
    pub async fn acknowledge_settings(&self, replace_newer: bool) -> Result<(), BridgeError>;
    pub async fn remove_broken(&self, name: String) -> Result<(), BridgeError>;
    pub async fn leave(&self, channel: [u8; 16]) -> Result<(), BridgeError>;                          // drops that channel's QR image (R6)
    pub fn qr_image(&self, n: u64) -> Option<Zeroizing<Vec<u8>>>;   // for the qr scheme: the current counter and generation only
    pub async fn set_socks5_proxy(&self, proxy: Option<String>) -> Result<(), BridgeError>;
    pub async fn probe_server(&self, url: String) -> Result<ProbeResult, BridgeError>;
}
pub trait KeyStore: Send + Sync { fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>; fn set(&self, key: &[u8; 32]) -> Result<(), KeyStoreError>; fn delete(&self) -> Result<(), KeyStoreError>; }
pub enum Confirmation { ResetLocalData, SetProxy(Option<ProxyShown>), AcknowledgeSettings { proxy: Option<ProxyShown>, rereads: bool },
                        ReplaceNewerSettings { proxy: Option<ProxyShown> }, RemoveBroken { name: Option<String>, reason: StoreError },
                        ReplaceBroken { reason: StoreError }, Unlock }
pub enum ConnectionState { Connecting, Connected, Retrying, ServerFull, UnsupportedServer, ProxyRefused }
pub enum ProbeResult { Supported, Unsupported, Unreachable, ProxyRefused, NotYet }
pub enum BridgeError { Core(Error), Locked, KeyLost, KeychainUnavailable, AlreadyRunning, Cancelled, Suppressed { retry_after_ms: u64 }, FileIo }   // crosses as the tagged union of R5
```

```ts
// generated.ts (R5), for example
export type ChannelId = string & { readonly __brand: 'ChannelId' };
export const commands: { send(channel: ChannelId, body: string, displayName: string | null): Promise<Result<SentView, BridgeError>>; /* … */ };
```

`call` MUST NOT be used for a command that R16 confirms, that R6 gives a file, a raw body or an image, or whose result carries events (R7): those have their own methods. `KeyStore` has one production implementation over `keyring` and `keyring-core`, and one in-memory implementation for tests (R1). The pull request that adds each dependency justifies it in one sentence (AGENTS 8): `tauri` (without `compression`), `tauri-plugin-dialog` (file dialogs only), `rfd` (`=0.16.0`), `tauri-specta` and `specta`, `serde`, `tokio`, `tokio-tungstenite`, `tokio-rustls`, `rustls` with `ring`, `rustls-native-certs`, `keyring` and `keyring-core`, `qrcode`, `xattr` (macOS only), and `zeroize`.

**PR slices** (AGENTS 14): (a) the workspace, its lints, profile, `clippy.toml` and bans, and the doc-lint checks (R1–R3); (b) `key.rs`, the instance lock, and unlock, lock and reset (R15–R17, without the sockets); (c) the host without sockets: calls, events, reconcile, the writer queues, the tick and the confirmations (R9–R11, R7's event handling); (d) `socks5.rs` and `socket.rs` with the probe (R12, R14); (e) backoff and connection state (R13, R7's `connection-state`); (f) the commands, the mirror types, the raw commands, the QR scheme and the web view configuration (R4–R6, R7's `core-event`, R8); (g) the exit test and the CI job (R18).

## Security

- The web view holds no key, no socket, no file, no `.chatcfg` bytes and no invitation text (R4, R6). What reaches it is what the user reads or types: message text, names, fingerprints, a QR text the user pastes to import, and the export password while it is on screen, as bytes that the page zeroes when it goes away (typescript-svelte skill). An injected script has the power of the UI, which is a documented residual:
  - it can read the open channels' messages and fingerprints, and carry them out through the commands themselves, by creating a channel on its own server and sending there, or by probing a server whose host name spells the data (resolved by the system resolver when no proxy is set);
  - it can leave channels one by one, and mark a key as verified, which forges the trust mark of spec 022-peers-tofu;
  - it can probe hosts and ports of the local network one at a time, and time the answers;
  - it cannot take out the storage key, a channel key or an identity key, since the invitation QR is an image it cannot read;
  - it cannot erase the local data, drop or change the proxy, accept settings without the previous proxy, remove a broken channel, replace one, or unlock again after a lock without a native confirmation whose text it cannot compose and which it cannot repeat at will (R9, R16);
  - it can choose the moment and the argument of a confirmation, for instance a remote proxy sent in place of the one the user typed, just when the user expects a dialog, and it can keep one kind of confirmation suppressed by raising it every 60 s. The per-kind button labels of R9 make a substitution visible; both are residuals of the power of the UI.
  The CSP, the permission handler, the navigation handler and the capability list (R8) keep scripts out, and spec 050-desktop-mvp renders every message text and name as text, never as HTML.
- The invitation QR is shown as a cross-origin image. A script cannot read it through a canvas or a fetch (R6, R8), but pixel-stealing side channels on rendered cross-origin content (SVG filter timing, as in GPU.zip in 2023) exist in browser engines; the QR is on screen only while the user shows it. This is a documented residual.
- Every host name is resolved by the proxy when one is set (R12), and one plan is one proxy username, so Tor gives one circuit per plan (spec 027-core-api R10). A proxy that selects no authentication is refused rather than used, so circuits never silently merge. The certificate check makes no network request (R12), so no revocation or intermediate fetch leaves outside the proxy. Plain WebSocket runs only to a `.onion` host through a loopback proxy, which is spec 027-core-api R10's rule and is not repeated here.
- TLS is 1.3 only, with no resumption and no ticket (R12, ADR 0040). These are documented residuals, each exposing the transport and never a message (`docs/spec.md` §4):
  - a revoked certificate that has not expired is accepted, since no revocation data is fetched;
  - the roots are those of the operating system's store, so a root the user or an employer added (a TLS-inspection box) is trusted, and the store's partial distrust rules and Certificate Transparency are not applied;
  - `rustls-native-certs` reads `SSL_CERT_FILE` or `SSL_CERT_DIR` instead when either is set in the app's environment. The `WEBVIEW2_*` and `WEBKIT_INSPECTOR*` variables are refused (R8); other environment set by a same-user launcher is out of the model of `docs/spec.md` §8.
- The plans of one device connect at the same moments (unlock, network return), so a server that holds several of its plans can link their circuits by timing. The per-plan circuits of spec 027-core-api R10 separate servers, and one server holds more than one plan of a device only when a plan's channel limit splits them. This is a documented residual.
- The key goes from the keychain into `StorageKey` through a zeroed array (R16), never into the web view or a log. Within the user's session, any process of that user can read the keychain entry and the files. `docs/spec.md` §8 documents this, and it is not changed here. An entry written before the first run is discarded, and the entry is bound to its data directory's path (R16).
- No transient keychain or file-system failure draws a new key, a key is used only after it reads back, and one instance holds the directory (R15, R16), so no path makes the app write a new key over data it can no longer read. A keychain entry replaced by another key of the same path makes every file read as `Corrupt`, not as `KeyLost`; the user sees the broken channels and the settings reset of spec 027-core-api R1 and R2. A data directory that moves (a renamed home folder, a migration to an account with another name) no longer finds its entry and reads as `KeyLost`. Both are documented residuals.
- No command waits on a socket, and `lock` waits for no network write (R10, R17), so a server that stops reading cannot stop the device from locking.
- These copies are not zeroed: Tauri's request buffer (R6), the image the web view decodes from the QR, and the copy of the export password the page holds until it zeroes it. This matches `docs/spec.md` §8 "FFI boundary".
- A termination that skips the app's quit path (the macOS Dock's Quit, logout) drops the `Device` without `flush` (R17), losing only the cursor and `synced_at` since the last commit; a documented residual.
- WebView2 may show its own prompt for a web permission that the header does not name, and WKWebView shows a "Paste" callout when a script reads the clipboard inside a click handler, which one more click accepts (R8). Both are documented residuals.
- The saturation of R5 cannot change the order a message is shown in, since the core delivers the order (architecture skill §7). It only keeps an absurd server time from wrapping around in the page.

## Public API changes

None. The bridge wraps spec 027-core-api as it stands, together with the `generate_storage_key` that spec 040-uniffi R8 adds.

## Test cases

- T01 (covers R1): `check_s041_t01_r01_desktop_workspace`: the desktop `[lints]` with one root entry removed or lowered from `deny` to `warn` fails, as do a different release profile and a lock with another `libsodium-sys-stable`; the real files pass; `grep -rn 'unsafe' clients/desktop/src-tauri/src` finds nothing; `cargo clippy` in the desktop workspace accepts a call of `SystemTime::now` in `host.rs`.
- T02 (covers R2): `check_s041_t02_r02_desktop_bans`: a desktop `deny.toml` missing `sha1`, with a wrapper that R2 does not list, with an advisory ignore that R2 does not list, or with a changed `[licenses]` fails; the real file passes; `cargo deny check` green; `cargo tree -i aws-lc-rs`, `cargo tree -i openssl-sys` and `cargo tree -i brotli` find nothing.
- T03 (covers R3): `check_s041_t03_r03_amendments`, once this spec is `accepted`: AGENTS 2 and 24, §8 and §9 name what R3 lists, and the typescript-svelte skill names the `qr` scheme and the CSP of R8.
- T04 (covers R4): `s041_t04_r04_command_list`: the specta commands and the raw commands together equal the list of R4; no command signature carries `now`; every command that reaches `Dialogs` is `async`.
- T05 (covers R5): `s041_t05_r05_types`: a 31-character or uppercase channel id → `BadLength` with nothing committed; a `Received` with `received_at` 2^60 crosses as 2^53 − 1; `export_bindings` writes `generated.ts`, and `git check-ignore` names it and `src-tauri/gen/`.
- T06 (covers R6): `s041_t06_r06_raw_bodies`:
  - `import_file` with a JSON body → `BadPayload`; with a raw wrong password → `BadPassword`, and the command's copy is zeros afterwards; with no pending file → `Cancelled`.
  - `import_qr` of an invitation whose directory is `Corrupt` asks `ReplaceBroken` once; declined → `Cancelled` and the entry kept; accepted → the channel imported.
  - `choose_chatcfg` with a 1 086-byte file → `BadConfig`, with a FIFO → `FileIo` and the FIFO never opened, dismissed → `Cancelled`.
  - After a declined `ReplaceBroken`, the kept slot is empty.
  - `export_file` dismissed → `Cancelled` and no `Device` call; to an unwritable path → `FileIo` and no password; its response is binary, not JSON.
  - `export_qr` returns a `qr:` URL whose response is an SVG with `Cache-Control: no-store` and no `Access-Control-Allow-Origin` header, and the URL stops answering after `lock`.
- T07 (covers R7): `s041_t07_r07_events`: a `Message` from `on_frame` reaches the `Sink` as `core-event`; an `UnsupportedServer` reaches it only as `connection-state` `unsupported_server`; `send` returns no `events`; `regenerate_identity` after an own-key alert closes and reopens the socket, and the `key_retired` is published; `ServerFull` gives `server_full`, then `connected` 60 000 ms later with the socket still open; `lock` emits `locked`, and nothing after it.
- T08 (covers R8): `s041_t08_r08_webview_config`: `tauri.conf.json` has exactly the CSP of R8, `withGlobalTauri` absent, the asset protocol disabled, the `Permissions-Policy` header and the window `incognito`; `build.rs` declares the commands of R4; the capability file grants exactly their permissions and `core:event:allow-listen`, with no `dialog:` and no `core:default`; the navigation handler refuses `https://example.org/`; the macOS `Info.plist` names no `NS*UsageDescription` key and the entitlements no camera or microphone; no source calls `enable_clipboard_access`; with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` set, the app opens no window; on the Linux runner, in the window the app builds, a geolocation request and `Notification.requestPermission()` end denied.
- T09 (covers R9): `s041_t09_r09_host_and_dialogs`: `Host` is built and unlocked in a plain `tokio` test with a channel `Sink` and fixed `Dialogs`; a second confirmation while one is open → `Cancelled`; a declined `reset_local_data` makes a second one within 60 000 ms return `Suppressed` with no dialog; each backend's dismissal result (rfd `Cancel`) and a `Custom` of the safe label map to a decline; a fixed `Dialogs` that answers yes after 10 ms is a decline; a request while the main window is unfocused → `Cancelled`; a file dialog while a confirmation is open → `Cancelled`, and any dialog within 3 000 ms of another closing → `Suppressed`; a main-thread closure and an emit still run while a confirmation is open; every locale of `src-tauri/strings/` has the English keys and placeholders, distinct action labels, and no `&` or `_`; each failed re-check gives the result R9 names; a `SetProxy` for `127.0.0.1.nip.io:1080` is shown as "on another computer"; `remove_broken` of an unknown name → `UnknownChannel` with no dialog; ticks keep their 1 000 ms rhythm while a confirmation is open; `lock` during an open confirmation, a `reset_local_data` one included, ends at once, and a later yes of any but the reset returns `Locked` and changes nothing; while locked, `set_socks5_proxy` returns `Locked` with no dialog.
- T10 (covers R10): `s041_t10_r10_reconcile`:
  - After `create_channel` a socket task exists for the new plan `id`, and after `leave` of its only channel it is cancelled.
  - A `send` puts its `publish` on the plan's queue before the command returns, and 50 concurrent `send`s and ticks put their `publish`es on the socket in `client_ref` order.
  - A socket closed with a `subscribe` queued, then reopened: the new socket's first frame is not that `subscribe`.
  - A peer that never reads makes the queue close the socket and does not block `lock`.
  - A call runs on a blocking thread, not on the runtime's worker. A frame tagged with an older generation is dropped, and a closure queued before `lock` that runs after the next `unlock` does not touch the new `Device`. A panic inside `call` returns `Core(Internal)`, and a panic in a plan task is followed by a reopen.
- T11 (covers R11): `s041_t11_r11_tick`: with a paused `tokio` clock, 5 000 ms after `unlock` give 5 calls of `on_tick`, the first at 1 000 ms, and a 4 000 ms stall gives one delayed tick, not a burst.
- T12 (covers R12): `s041_t12_r12_socket`:
  - Against a test SOCKS5 server, the `CONNECT` carries `ATYP` 3 with the host name and the plan's username with an empty password, and no DNS query is made. A server that selects method `0x00`, replies with `VER` 4, or fails authentication gives `proxy_refused`. A reply whose bound address is a domain of 255 bytes is read in full.
  - Against a local TLS server with a test root (a `cfg(test)` constructor of the client configuration), TLS 1.2 is refused, and a second connection makes a full handshake with no ticket and no PSK. A leaf whose CRL distribution point and OCSP and AIA addresses point at a local listener completes its handshake, and the listener sees no connection.
  - The WebSocket request carries exactly the headers of §6 and no `Origin`. A 70 001-byte frame closes the socket, a text frame closes it, and 75 000 ms of silence closes it.
  - A connect to an onion host through the proxy is allowed 60 000 ms, and one to another host 30 000 ms.
- T13 (covers R13): `s041_t13_r13_backoff`: with a paused clock, the reopen delays are 1 000, 2 000, 4 000 … 60 000, 60 000 ms, and reset after 60 000 ms connected; a socket that the host closed for silence is reopened with the backoff; after `UnsupportedServer` no reopen happens until a new `unlock`; after `Reconnect` a reopen follows the backoff; after `proxy_refused` no reopen happens until `set_socks5_proxy`.
- T14 (covers R14): `s041_t14_r14_probe`: two probes at once run one after the other; a server that sends `hello` with version 1 → `Supported`; one with versions 2 and 3 → `Unsupported`; one that sends a `push` first → `Unreachable`; one that sends nothing → `Unreachable` 30 000 ms after its handshake; while `settings_reset` → `NotYet`; a URL with a path → `BadConfig`.
- T15 (covers R15): `s041_t15_r15_data_dir`: on Unix the directory is created with mode 0700; on macOS `xattr::get` reads back the exact bytes of the backup exclusion attribute; on Windows the path is under `%LOCALAPPDATA%`; a second `Host` over the same `instance.lock` gets `AlreadyRunning` from `unlock` and `reset_local_data`, and succeeds once the first releases it; an unreadable `channels/` makes `unlock` return `FileIo` with the keychain untouched; an `unlock` issued during a `reset_local_data` waits for it, then starts fresh.
- T16 (covers R16), `s041_t16_r16_unlock`, over the in-memory `KeyStore` unless stated:
  - First run → a key written and the device open. Second run → the same key.
  - Entry deleted with data present → `KeyLost` and nothing written. A 31-byte entry → `KeyLost`.
  - A 32-byte entry with no data → a new key drawn and written in its place. An entry for another data directory path is neither read nor deleted, and the same directory reached through a symlink opens with the same key.
  - A read-back that differs → `KeychainUnavailable`, the entry deleted, nothing opened. A keychain error → `KeychainUnavailable` and nothing written.
  - `unlock` twice → one open; an `unlock` queued behind a `lock` that follows the first open, with no confirmation asked → `Cancelled`, still locked; `lock` during an `unlock` → locked once the `unlock` ends; the first `unlock` of the process asks nothing, and one after a `lock` asks `Unlock`, declined → `Cancelled` and still locked.
  - `acknowledge_settings(true)` with `settings_reason` `UnsupportedVersion` and the flag already clear asks `ReplaceNewerSettings`; with the flag set as well, only that dialog is shown; with the reason `Io` and a re-read that finds a newer file, the newer file is kept.
  - Each confirmation of R16 declined → `Cancelled` with nothing changed. A reset in a process that never unlocked deletes the entry. `reset_local_data` accepted while unlocked → locked first, then a new key and an empty device at the next `unlock`; with a directory that cannot be deleted → `FileIo` and the entry kept.
- T17 (covers R17): `s041_t17_r17_lock`: after `lock`, `channels` → `Locked`, and the kept import slot is empty; quitting while a confirmation is open ends locked and exited after one lock, and a yes given to an open `Unlock` or reset dialog after the quit changes nothing; the macOS menu has no predefined Quit item; a panic in `on_frame` emits `locked`, no reconnect follows, and nothing is flushed; after a panic poisoned the lock, `lock` then `unlock` gives a working device; the tick stops; each open socket got `on_disconnect`; a task in its backoff sleep or its connect is ended before `locked`; a `send` in flight when `lock` starts leaves no task and no `Sink` call after `locked`; a failing `flush` or a poisoned lock still drops the device.
- T18 (covers R18): `s041_t18_r18_phase4_exit`: the run of R18.

## Vectors

None. The bridge calls `Device` in-process, in Rust, so every vector already reaches it through `cargo test` in the root workspace. The boundary to check is the IPC one, which T05 and T06 cover.

## Acceptance criterion

`cargo test` in `clients/desktop/src-tauri/` green, T18 included; the CI job `desktop` green; the documentation lint green. With spec 040-uniffi green as well, phase 4 closes (`docs/spec.md` §10). Non-automatable:
- a second person reads `commands.rs`, `build.rs`, the capability file and `tauri.conf.json` together and confirms that the web view can reach nothing beyond R4;
- on Windows and on Linux, a debug build loads a page that tries `getImageData`, `toDataURL`, `createImageBitmap` with an `OffscreenCanvas`, and `fetch` on the `qr:` URL, and each fails (measured on macOS on 2026-09-26);
- on Linux, pressing Return on a confirmation dialog does not accept it;
- on Windows, the entry that `unlock` writes in the real Credential Manager has the `persistence` attribute `Local` (a check on the real store, which the architecture skill keeps out of the automated tests);
- on macOS, a clipboard read inside a click handler shows the "Paste" callout of the Security section and nothing more, and Esc on a confirmation declines it or does nothing;
- on Linux, the synchronous rfd dialog of R9 inside `spawn_blocking` opens and answers without stopping the event loop.

## Out of scope

- The Svelte UI, its state modules, how it re-reads after `StatusChanged`, and rendering text as text (spec 050-desktop-mvp).
- When the app locks on its own (session lock, timeout), and the app password for a system with no keychain (spec 053-device-security, `docs/spec.md` §8).
- Scanning QR codes, and drawing the verification QR (specs 054-qr-invite and 055-verify-ui).
- Signing, notarisation and reproducible builds (spec 060-reproducible-builds).
- Android and iOS (spec 040-uniffi, specs 051-android-mvp and 052-ios-mvp).

## Open questions

None. Decided with the human reviewer on 2026-09-26 (`docs/audit-log.md`, "Phase 4 drafts", Q2 and Q3, and "Audit L", L-Q1 to L-Q4 and L-Q6 to L-Q8).

## History

- 2026-09-26 draft
- 2026-09-26 revised after audit L round 1 (`docs/audit-log.md`): the measured wrapper list and the copied deny sections; profile, `clippy.toml` and the libsodium pin; generated types not committed and raw commands outside specta; the file dialog and the QR image on the Rust side; the host takes the events out of every result; one ordered writer queue per plan; generations and a waiting `lock`; the connection states defined; certificates checked with no network request; a strict SOCKS5 client; the instance lock, the read-back and the planted entry; native confirmations; the exit test's server start made exact
- 2026-09-26 revised after audit L round 2 (`docs/audit-log.md`): ADR 0040 in place of 0039; the wrapper list, the added bans, the advisory ignores and the WebView2 loader measured again; the queue tied to its socket; `lock` in a safe order; the confirmations hardened and extended to spec 027's destructive actions; the keychain entry bound to its path and set to local persistence on Windows; I/O errors never read as "no data"; web permissions denied; the exit test's environment made exact
- 2026-09-26 revised after audit L round 3 (`docs/audit-log.md`): web permissions per engine with no `unsafe`; a native confirmation for every unlock after a lock; dialogs outside the lock, re-validated, with `Suppressed`; the replace confirmation in two steps; `acknowledge_settings(true)` always confirmed while a newer file stands; `unlock`, `lock` and reset serialised; stale closures kept off a new `Device`; the canonical path, `store_status` first and `Zeroizing` reads; the crate a library; the Time Machine value; the CI runners
- 2026-09-26 revised after audit L round 4 (`docs/audit-log.md`): confirmations through `rfd` directly, since the dialog plugin maps a dismissal to the second label; per-kind button labels and translated texts; the FIFO mutex never held across a dialog, and the lock steps one routine that reset runs inside its hold; the kept import slot emptied by `lock`; `replace_newer` only after its own dialog; spec 027 R3's texts; the poison cleared at lock; quitting without blocking the main thread
- 2026-09-26 revised after audit L round 5 (`docs/audit-log.md`): confirmations off the main thread (async rfd on macOS and Windows, blocking on Linux); an input-protection delay, focus, a shared slot with the file dialogs and a quiet period; build-time strings with checked locales; the quit path held to the end, a flag against the exit loop, and the macOS Quit item replaced; a poisoned lock locks the device with no flush; the unlock count checked under the mutex; the keychain user from the parent directory; the re-check results per kind
