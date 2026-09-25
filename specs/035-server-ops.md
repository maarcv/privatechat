# 035 — Server operation: configuration, client address, logging, shutdown and the phase 3 exit test

Status: draft
Phase: 3
Related ADRs: 0022, 0038
Depends on: 027-core-api, 030-ws-protocol, 031-auth-channel-signature, 032-storage-ttl, 033-rate-limit-quotas
Blocks: 034-docker
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The protocol specs 030–033 describe what the server does on a connection. This spec describes the binary around them: how an operator configures it, how it finds a client's address behind a reverse proxy, the second listener for the onion service (ADR 0038), what it may write to its log, how it stops, and the test that closes phase 3 (`docs/spec.md` §10: a core↔server integration test through `Session`, and a log test without identifiers).

§6 "Operation" and §8 "Logging" set the bounds. The configuration holds the hostnames, the trusted proxies, the quotas and the database path. `X-Forwarded-For` is accepted only from a trusted proxy. There is no SQL logging, and no `channel_id`, `server_id` or IP in the logs: only aggregate counters and error codes. A CI test proves it under load. The configuration is read from environment variables and no file, so it needs no parser dependency (`docs/audit-log.md`, "Phase 3 drafts", P4).

This spec also takes over spec 100, the log test that was parked until a crate emitted logs (`docs/audit-log.md`, "Phase 3 drafts", P3). The server is that crate. R5, R6 and R7 below are that spec's R1, R2 and R3 under this number, and the parked file is deleted.

**In plain words.** The operator sets a few environment variables: the addresses people will put in their channels, where the database lives, and which reverse proxy to trust. Anything misspelt stops the server at once with a clear message, rather than letting it run half-configured. The server logs almost nothing: that it started, that it stopped, errors by kind, and every ten minutes a line of totals. It never logs a channel, a message id or an IP address, and a test proves it. On stop, it finishes saving what it was already writing, says goodbye to every connection and closes the database cleanly. The final test runs two real apps' cores against a real server over real sockets, and checks that every message arrives exactly once, through a reconnection and a server restart.

**PR slices** (AGENTS 14): (a) configuration, listeners and exit codes (R1, R2, R9); (b) the client address (R3); (c) logging, the log tests and the lint (R4–R7); (d) shutdown (R8); (e) the exit test (R10).

## Requirements

**Configuration and listeners**

- R1 The server MUST read its configuration once, at start-up, from the environment variables of the table "Configuration" and from nothing else. A missing `PRIVATECHAT_URLS`, a value outside its range, two URLs with the same host, or a set variable whose name starts with `PRIVATECHAT_` and is not in the table MUST stop the server before it opens the database, with a message that names the variable and not its value, and with exit code 2. Each URL MUST be checked with `relay::url_host` of spec 031-auth-channel-signature R8, and the resulting hosts are the `hosts` of spec 031.
- R2 The server MUST listen on `PRIVATECHAT_LISTEN` and, when it is set, also on `PRIVATECHAT_ONION_LISTEN`, serving the same route (spec 030-ws-protocol R3) on both. A connection on the onion listener carries no client address, and its `X-Forwarded-For` is ignored.
- R3 On the main listener, the client address MUST be the socket's peer address, unless that peer is in `PRIVATECHAT_TRUSTED_PROXIES` and the request carries `X-Forwarded-For`. In that case it is the rightmost address of the header's list, all headers joined in order, that is not in the trusted list, or the leftmost when all are trusted. A header from a trusted peer that does not parse as a list of IP addresses MUST get HTTP 400 with an empty body, and a header from any other peer MUST be ignored.

**Logging**

- R4 The server MUST log through `tracing` to standard error, with no colour, at the level of `PRIVATECHAT_LOG`, and only these events: start-up (version, listener addresses, number of configured URLs), stop, each start-up refusal by reason, each database error by SQLite result code, and, every 600 000 ms at `info`, one line of totals (connections open, subscriptions open, blobs stored, blobs purged, refusals per error code, closes per status, database bytes). An event at `debug` or `trace` MAY name a channel only by `short_id`, the 8 lowercase hex characters of its first 4 bytes. No event may carry a `server_id`, a `client_ref`, an IP address, an `X-Forwarded-For` value, `pk_ch`, `sig`, a nonce, blob bytes or SQL text. No `log` logger is installed, `axum` is built without its `tracing` feature, and no SQLite trace hook is set (spec 032-storage-ttl R12).
- R5 A test MUST install an in-memory `tracing` subscriber at `trace` level over the run of R10, and assert that the captured output contains neither the lowercase hex nor the base64 of `K_ch`, `sk_u`, `sk_ch`, `K_msg`, `K_hdr` or any `mk` of the run, and no full `channel_id`, `server_id`, `client_ref` or client IP (`docs/spec.md` §6 "Operation", §8 "Logging").
- R6 The same test MUST assert that every `channel_id` and every `pk` that reaches the captured output appears only as its `short_id` (AGENTS 19).
- R7 `scripts/doc_lint.sh` MUST fail while any tracked `*.rs` file contains `tracing::` and this spec is `draft` or `in review`, so that no log line lands before the rules of R4–R6 are accepted.

**Shutdown and exit codes**

- R8 On SIGTERM or SIGINT, the server MUST stop accepting connections, stop reading frames, let the writer store and answer every request already queued, close every connection with status 1001, run `PRAGMA wal_checkpoint(TRUNCATE)`, close the database and exit with code 0, all within 10 000 ms of the signal; past that, it MUST exit with code 1.
- R9 The exit code MUST be 2 for a configuration error (R1), 3 when the database is refused at start-up (spec 032-storage-ttl R3), 1 for any other fatal error, a listener that cannot bind included, and 0 only after R8.

**Phase 3 exit test**

- R10 `crates/server/tests/phase3_exit.rs` MUST start the server in the test process, on `127.0.0.1` with an ephemeral port, a temporary database and a `ManualClock` that also gives the test its `now`. It then runs two `Device`s of spec 027-core-api over `DataDir`s in temporary directories. The test itself plays the client of spec 027 R11: it opens a WebSocket to the server for each planned connection (plain `ws://`, because TLS belongs to the reverse proxy), passes frames both ways, ticks every 1 000 ms of the clock, and reconnects on `Event::Reconnect`. Device A creates a channel with TTL 86 400 on `wss://127.0.0.1:<port>`, which is also the server's `PRIVATECHAT_URLS`, and device B imports its QR. Each device then sends 300 messages, one every 3 000 ms. B's socket is dropped after its 100th message, and the server is stopped (R8) and started again on the same file after the 200th. The test MUST end with every message delivered exactly once to the other device, a `Delivered` event for each on its sender, no error other than those the test injected, and, after the clock moves 86 460 000 ms on and one purge runs, no row left in the table.

## Limits

**Configuration** (integers in decimal, bytes with no suffix)

| Variable | Default | Range | Used by |
| --- | --- | --- | --- |
| `PRIVATECHAT_URLS` | — (required) | 1..=8 URLs separated by `,`, each of the grammar of spec 011 R5, hosts distinct | spec 031 R8 |
| `PRIVATECHAT_LISTEN` | `0.0.0.0:8080` | an IP socket address | R2 |
| `PRIVATECHAT_ONION_LISTEN` | absent | an IP socket address other than `PRIVATECHAT_LISTEN` | R2 |
| `PRIVATECHAT_TRUSTED_PROXIES` | empty | 0..=16 IP addresses or CIDR blocks separated by `,` | R3 |
| `PRIVATECHAT_DB` | `/data/messages.db` | a path | spec 032 |
| `PRIVATECHAT_MAX_DB_BYTES` | 8 589 934 592 | 67 108 864..=2^62 | spec 032 R8 |
| `PRIVATECHAT_MAX_CONNECTIONS` | 4 096 | 1..=1 000 000 | spec 033 R10 |
| `PRIVATECHAT_CHANNEL_PUBLISH_PER_MIN` | 120 | 1..=100 000 | spec 033 R6 |
| `PRIVATECHAT_CHANNEL_BYTES_PER_MIN` | 4 194 304 | 64 673..=2^40 | spec 033 R6 |
| `PRIVATECHAT_CHANNEL_MAX_BLOBS` | 20 000 | 1..=10 000 000 | spec 033 R7 |
| `PRIVATECHAT_CHANNEL_MAX_BYTES` | 67 108 864 | 64 673..=2^40 | spec 033 R7 |
| `PRIVATECHAT_IP_UNAUTH_CONNECTIONS` | 20 | 1..=10 000 | spec 033 R8 |
| `PRIVATECHAT_IP_NEW_PER_MIN` | 60 | 1..=100 000 | spec 033 R8 |
| `PRIVATECHAT_LOG` | `warn` | `error`, `warn`, `info`, `debug`, `trace` | R4 |

Out of range, absent when required, or unknown with the `PRIVATECHAT_` prefix: exit code 2 (R1).

| Other input | Range | Out of range |
| --- | --- | --- |
| `X-Forwarded-For` from a trusted peer | a list of IP addresses separated by `,` and optional spaces, ≤ 8 KiB in all headers | HTTP 400 |
| Shutdown | ≤ 10 000 ms after the signal | exit code 1 |

## Interface

```
crates/server/src/main.rs                 start-up, listeners, signals, exit codes (R2, R8, R9)
crates/server/src/config.rs               Settings::from_env (R1)
crates/server/src/client_addr.rs          the address of R3, CIDR matching with std::net only
crates/server/src/log.rs                  the subscriber, short_id and the totals line (R4)
crates/server/src/tests/ops.rs            s035_* unit tests
crates/server/tests/phase3_exit.rs        R10, and the log tests R5 and R6 over the same run
scripts/doc_lint.py                       check_s035_t07_r07_log_rules_accepted_before_logging (R7)
```

```rust
pub(crate) struct Settings {
    pub(crate) hosts: Vec<String>, pub(crate) listen: SocketAddr, pub(crate) onion_listen: Option<SocketAddr>,
    pub(crate) trusted_proxies: Vec<IpNet>, pub(crate) db: PathBuf, pub(crate) max_db_bytes: u64,
    pub(crate) max_connections: u32, pub(crate) channel: ChannelLimits, pub(crate) ip: IpLimits, pub(crate) log: Level,
}
impl Settings { pub(crate) fn from_env(vars: impl Iterator<Item = (String, String)>) -> Result<Settings, ConfigError>; }
pub(crate) struct IpNet { addr: IpAddr, prefix: u8 }   // hand-written, no crate
pub(crate) fn client_addr(peer: IpAddr, forwarded: &[&str], trusted: &[IpNet]) -> Result<IpAddr, BadForwarded>;
pub(crate) fn short_id(bytes: &[u8]) -> String;   // 8 lowercase hex characters of the first 4 bytes
```

`from_env` takes the variables as an iterator so that tests need not touch the process environment. Dependencies added, each justified in its pull request (AGENTS 8): `tracing` (`default-features = false`, feature `std`) and `tracing-subscriber` (`default-features = false`, features `fmt` and `std`). Dev-dependencies for R10: `privatechat-core` with `test-support` and `privatechat-store`.

## Security

- The log is the easiest place for metadata to leak and the first place a seizure looks. R4 lists what may be logged, and anything not listed is forbidden. R5 and R6 check the rule mechanically over a full run, and R7 stops logging code from landing before the rule is accepted.
- R3 trusts `X-Forwarded-For` only from the operator's own proxy. Any other client could otherwise write a fake address into the header and dodge the per-IP limits of spec 033. The address is used for those limits only and is never logged (R4) or stored (spec 033 R9).
- The onion listener (R2) must not be reachable from outside the host or the container network. Otherwise anyone could skip the per-IP limits by connecting to it directly. Spec 034-docker binds it to the internal network only.
- R1 refuses to start on any doubt rather than run with a default the operator did not intend. An unknown `PRIVATECHAT_` name is most often a typo in a quota.
- R8 answers every request already in the writer's queue, so a stop loses no acknowledged blob. A blob whose frame was still in flight gets no `ack`, and its client republishes it after reconnecting (spec 021-channel-session R8).
- The configured URLs are public (they are in every config of the server's channels) and may be logged at start-up as a count. Their text is not logged, so that a log line does not tie the server to its onion name.

## Public API changes

None in `core`. At acceptance:
- `docs/spec.md` §6 "Operation" gains the environment variables, the onion listener and the exit codes. §8 "Logging" and AGENTS 19 point to this spec for the log test (already done when spec 100 was folded in).
- The `.github/CONTRIBUTING.md` section "Running the CI locally" gains `cargo test -p privatechat-server`.

## Test cases

- T01 (covers R1): `s035_t01_r01_configuration`: the defaults with only `PRIVATECHAT_URLS` set; `PRIVATECHAT_URLS` absent → exit code 2; `PRIVATECHAT_MAX_CONECTIONS` (misspelt) → exit 2, the message names the variable; `PRIVATECHAT_CHANNEL_MAX_BYTES=100` → exit 2; nine URLs → exit 2; `wss://a.org,ws://<56>.onion` → two hosts; `wss://a.org,wss://a.org:9001` → exit 2 (same host); a value never appears in any message.
- T02 (covers R2): `s035_t02_r02_two_listeners`: both listeners answer the upgrade; a connection on the onion listener with `X-Forwarded-For` set → no address in its state; `PRIVATECHAT_ONION_LISTEN` equal to `PRIVATECHAT_LISTEN` → exit 2.
- T03 (covers R3): `s035_t03_r03_client_address`: an untrusted peer with a header → the peer's address; a trusted peer with `1.2.3.4, 10.0.0.2` where `10.0.0.0/8` is trusted → `1.2.3.4`; two headers joined in order; all entries trusted → the leftmost; `not-an-ip` from a trusted peer → 400, no upgrade; an IPv6 peer inside a trusted `/64`.
- T04 (covers R4): `s035_t04_r04_log_events`: at `info` over a short run with a manual clock → the start line, one totals line per 600 000 ms, and the stop line, and nothing else; at `warn` → no line in a clean run; a `debug` event about a subscription carries `short_id` of its channel; a CI step `s035_t04_r04_no_log_crate` checks that `cargo tree -e features -p privatechat-server` shows `axum` without `tracing`, and that no `log` implementation is registered.
- T05 (covers R5): `s035_t05_r05_no_secret_reaches_the_log`: over the run of R10 under a `trace` subscriber, the captured output contains none of the listed secrets in hex or base64, and no full `channel_id`, `server_id`, `client_ref` or `127.0.0.1`.
- T06 (covers R6): `s035_t06_r06_identifiers_are_truncated`: every 8-hex token that matches the start of a `channel_id` or `pk` of the run is followed by no further hex of it; a `debug` event built with a `channel_id` shows exactly its `short_id`.
- T07 (covers R7): `check_s035_t07_r07_log_rules_accepted_before_logging` in `scripts/doc_lint.py`, with its own fixture: a tracked `*.rs` file containing `tracing::` plus this spec at `Status: draft` or `in review` → the lint fails; at `accepted` → it passes.
- T08 (covers R8): `s035_t08_r08_graceful_shutdown`: with 50 requests queued in a paused writer, SIGTERM → all 50 stored and acknowledged, then every client sees close 1001, the WAL file is empty, and the exit code is 0 within 10 000 ms; a writer hung by a test hook → exit code 1 after 10 000 ms.
- T09 (covers R9): `s035_t09_r09_exit_codes`: a configuration error → 2; a database with `user_version` 2 → 3; a port already bound → 1.
- T10 (covers R10): `s035_t10_r10_phase3_exit`: the run of R10, with its assertions, and its duration on the CI runner recorded in the pull request.

## Vectors

None: no format. The run of R10 uses the vectors of the specs it exercises only through their code.

## Acceptance criterion

`cargo test -p privatechat-server s035_` green, `phase3_exit.rs` included; `scripts/doc_lint.sh` green with the check of R7; clippy and `cargo deny --all-features check` green. With specs 030–034 `implemented`, this closes the automatable part of the phase 3 exit criterion (`docs/spec.md` §10). `docker compose up` and `deploy/README.md` are spec 034-docker's.

## Out of scope

- The reverse proxy, TLS, the onion service configuration and the image (spec 034-docker).
- A metrics endpoint, a health endpoint and hot reloading: none in v1. The totals line is the only telemetry, and a configuration change means a restart.
- The clients' log level and subscriber (specs 050–052).

## Open questions

None.

## History

- 2026-09-25 draft; takes over the log test of spec 100 (its R1–R3 become R5–R7) and deletes that file (`docs/audit-log.md`, "Phase 3 drafts", P3)
