# ADR 0037 — Expose one `Device` handle at the core boundary

Date: 2026-09-25 · Status: accepted

## Context
`docs/spec.md` §9 and AGENTS 20 give the clients four opaque handles — `Config`, `Channel`, `Session`, `Settings` — which are passed to each other by value: `Channel::open(config, store)`, `Session::new(url, channels)`, `Channel::leave(self)`. Audit J (`docs/audit-log.md`, J-C4, J-D1, J-D2) found that uniffi cannot express this: its objects are shared `Arc`s with `&self` methods, never moved and never borrowed out, and a `Box<dyn Store>` cannot cross. It also found that a stored channel could not be reopened after a restart, because no call gave back its `Config`, and that an open channel exposed neither its identity nor its invitation.

## Decision
The core exposes one opaque handle, `Device`, which owns the storage vault, every channel, the settings and one `Session` per planned connection, and whose calls name channels by `channel_id` and connections by an id of its connection plan; `Config`, `Channel`, `Session` and the stores are crate-internal (spec 027-core-api).

## Alternatives considered
- Keeping the four handles and wrapping each in `Arc<Mutex<_>>` in spec 040-uniffi: every by-value call would need a new shape there, and the protocol decisions (who owns a channel while it is connected) would move into the bindings, twice.
- A `Session` that re-exposes every channel call by id, with `Channel` still a handle: two objects to lock in the right order, and the connection grouping still in each client.

## Consequences
- The bindings wrap one `Mutex<Device>`; each client holds one object and calls it by id.
- The grouping of channels into connections (16 per connection, one per channel behind a proxy) is computed once, in the core.
- `Device` can list broken channels and a lost settings file, which no single-channel handle could.
- Every call locks the whole device. Most calls are short; `import_file` and `export_file` run Argon2id at 64 MiB and a compaction can re-seal 64 MiB, so the bindings (specs 040-uniffi, 041-desktop-bridge) make every `Device` call off the UI thread.
- Affected: `docs/spec.md` §9, AGENTS 20, the rust skill; specs 021-channel-session, 027-core-api, 028-session-sans-io, 040-uniffi, 041-desktop-bridge.
