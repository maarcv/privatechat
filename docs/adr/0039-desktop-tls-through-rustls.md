# ADR 0039 — Open the desktop client's TLS connections with rustls, in a workspace of its own

Date: 2026-09-26 · Status: accepted

## Context
AGENTS 2 allows no cryptographic primitive outside libsodium anywhere in the workspace, and `deny.toml` bans `rustls`, `ring`, `aws-lc-rs` and `openssl` by name. TLS terminates at the reverse proxy on the server side (`deploy/`), so the server never needed a TLS stack. The desktop client does. Its sockets live in the Rust side of the Tauri process, since the web view is the least trusted part and cannot reach a SOCKS5 proxy (spec 041-desktop-bridge). The server accepts TLS 1.3 only (`docs/spec.md` §6 "Transport"). The operating system's TLS through `native-tls` does not do TLS 1.3 on macOS, where it uses Secure Transport. Tauri itself also brings crates that the root `deny.toml` bans (`sha2` and `brotli`, for its build-time asset handling), so the desktop crate could not join the root workspace in any case. The question came up while drafting phase 4 (`docs/audit-log.md`, "Phase 4 drafts", Q2).

## Decision
`clients/desktop/src-tauri/` is a Cargo workspace of its own, with its own `Cargo.lock` and its own `deny.toml`. That file keeps every ban of the root one, except for named wrapper exceptions. The desktop client opens its `wss://` connections with `rustls`, the `ring` provider, TLS 1.3 only and session resumption disabled, and verifies certificates against the operating system's trust store through `rustls-platform-verifier`.

## Alternatives considered
- `native-tls`, the operating system's stack: no new cryptographic crate, but no TLS 1.3 on macOS, so it cannot reach the reference server.
- The web view's own WebSocket: its browser engine already carries TLS, but it cannot connect through a SOCKS5 proxy with a per-plan username (spec 027-core-api R10), so the desktop client would lose Tor.
- `rustls` with its default `aws-lc-rs` provider: the same library with a C and assembly build that needs CMake, and a larger code base to trust than `ring`.

## Consequences
- The TLS layer protects only the transport. Message confidentiality and authenticity still come from libsodium in the core (`docs/spec.md` §4): a flaw in `rustls` or `ring` exposes what a network observer of a plain connection would see (the server name, timing and sizes, ciphertext), never a message or a key.
- AGENTS 2 names this as its second exception, next to the reference script of spec 015-test-vectors, and `docs/spec.md` §9 names the desktop TLS stack.
- The desktop workspace duplicates the root `[workspace.lints]` and `[bans]`, and the documentation lint checks that nothing was dropped (spec 041-desktop-bridge).
- Android and iOS keep their platform stacks (OkHttp over the platform's TLS, `URLSession`), so each platform's TLS fingerprint still reveals the platform, as §6 already documents.
- Affected: AGENTS 2, `docs/spec.md` §9; specs 041-desktop-bridge and 050-desktop-mvp.
