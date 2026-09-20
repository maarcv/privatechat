# ADR 0022 — Exchange server per channel, fixed at creation

Date: 2026-09-20 · Status: accepted

## Context
The project is open source and anyone will be able to deploy the server. The channel config already carried `server_url` (§5), but §6 assumed "a single connection per device" and `Session` took a single `host`, and it was not stated how the server is chosen when creating a channel or whether it can be changed later.

## Decision
Each channel lives on a single server, the one chosen by whoever creates it. The creation form pre-fills the `default_server_url` from the app settings —at installation, the compile-time constant `DEFAULT_SERVER_URL`, the project's server— and the user can change both the app default and the channel's value at that moment. A created channel does not change any basic channel parameter (`K_ch`, TTL, server): changing one means creating a new channel (ADR 0008). The client keeps one connection and one `Session` per server; a device with channels on N servers has N connections.

## Alternatives considered
- A single server per device: would force the whole group to accept one member's operator; incompatible with channels received by invitation.
- Hot server change (editing `server_url` locally): members with a different `server_url` would stop seeing each other with no error; importing a config with the same `channel_id` and a different server already yields `ConfigMismatch` (§5).
- `host` inside the `channel_id`: a DNS or port change would kill the channel; the `host` already goes inside the authentication signature (ADR 0010), which is where it protects.
- No default server: friction on every creation; the project can operate one and whoever does not want it changes it.

## Consequences
- The UI groups channels by `host` and opens one socket per group; `Session::new(host, channels)`.
- `settings.bin` in the `data_dir` (`default_server_url`, `lock_timeout`, proxy), same format as `state.bin` (ADR 0021).
- No server URL in the code outside `DEFAULT_SERVER_URL`; each *fork* puts its own.
- The project's server concentrates the metadata of those who do not change the default; this is stated in §1 "What it does not promise". Each server only sees the channels that live on it.
- `deploy/README.md` documents how to deploy one's own server (spec 034/035).
- Affected specs: 000-repo-layout, 020-store-files, 028-session-sans-io, 034-docker, 035-server-ops, 050, 051, 052 (creation form).
