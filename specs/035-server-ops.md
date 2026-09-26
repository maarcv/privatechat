# 035 — Server operation: configuration, client address, logging, shutdown and the phase 3 exit test

Status: draft
Phase: 3
Related ADRs: 0022, 0038
Depends on: 027-core-api, 030-ws-protocol, 031-auth-channel-signature, 032-storage-ttl, 033-rate-limit-quotas
Blocks: 034-docker, 041-desktop-bridge
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The protocol specs 030–033 describe what the server does on a connection. This spec describes the binary around them:
- how an operator configures it;
- how it finds a client's address behind a reverse proxy;
- the second listener for the onion service (ADR 0038);
- what it may write to its log;
- how it stops;
- the test that closes phase 3 (`docs/spec.md` §10: a core↔server integration test through `Session`, and a log test without identifiers).

§6 "Operation" and §8 "Logging" set the bounds:
- The configuration holds the hostnames, the trusted proxies, the quotas and the database path.
- `X-Forwarded-For` is accepted only from a trusted proxy.
- There is no SQL logging, and no `channel_id`, `server_id` or IP in the logs: only aggregate counters and error codes.
- A CI test proves it under load.

The configuration is read from environment variables and no file, so it needs no parser dependency (`docs/audit-log.md`, "Phase 3 drafts", P4).

This spec also takes over spec 100, the log test that was parked until a crate emitted logs (`docs/audit-log.md`, "Phase 3 drafts", P3). The server is that crate. R5 and R6 below are that spec's R1 and R2 under this number. Its R3, a lint against logging code landing before the rules, is dropped: AGENTS already forbids implementing a spec before it is accepted (audit K).

**In plain words.** The operator sets a few environment variables: the addresses people will put in their channels, where the database lives, and which reverse proxy to trust. Anything misspelt stops the server at once with a clear message, rather than letting it run half-configured. The server logs almost nothing: that it started, that it stopped, errors by kind, and every ten minutes a line of totals. It never logs a channel, a message id or an IP address, and a test proves it. On stop, it finishes saving what it was already writing, says goodbye to every connection and closes the database cleanly. The final test runs two real apps' cores against a real server over real sockets. It checks that every message arrives exactly once, through a reconnection and a server restart.

**PR slices** (AGENTS 14): (a) the library entry point, configuration, listeners and exit codes (R1, R2, R8, R10); (b) the client address (R3); (c) logging and the log tests (R4–R6); (d) shutdown and the crash test (R7, R9); (e) the exit test (R11).

## Requirements

**Configuration and listeners**

- R1 The server MUST read its configuration once, at start-up, from the environment variables of the table "Configuration" and from nothing else, reading the environment with `std::env::vars_os`. Any of these MUST stop the server before it opens the database, with a message that names the variable and not its value, and with exit code 2:
  - a missing `PRIVATECHAT_URLS`;
  - a value outside its range;
  - two URLs with the same host;
  - a variable whose name starts with `PRIVATECHAT_` and is not in the table;
  - such a name or value that is not UTF-8.

  Each URL MUST be checked with `relay::url_host` of spec 031-auth-channel-signature R8. The resulting hosts are the `hosts` of spec 031.
- R2 The server MUST listen on `PRIVATECHAT_LISTEN` and, when it is set, also on `PRIVATECHAT_ONION_LISTEN`, serving the same route (spec 030-ws-protocol R3) on both. A connection on the onion listener carries no client address, and its `X-Forwarded-For` is ignored.
- R3 On the main listener, the client address MUST be the socket's peer address, unless that peer is in `PRIVATECHAT_TRUSTED_PROXIES` and the request carries `X-Forwarded-For`. In that case it is the rightmost address of the header's list (all headers joined in order) that is not in the trusted list, or the leftmost when all are trusted. A header from a trusted peer that does not parse as a list of IP addresses MUST get HTTP 400 with an empty body. A header from any other peer MUST be ignored.

**Logging**

- R4 The server MUST log through `tracing` to standard error, with no colour, at the level of `PRIVATECHAT_LOG`, through a subscriber that `main.rs` installs with `log::init` once the configuration is read (never `run`, so that tests install their own), and, at `info` and above, only these events:
  - start-up: the version, the bound port of each listener as the fields `listen_port` and, when the onion listener is on, `onion_port`, whether the onion listener is on, and the number of configured URLs;
  - stop;
  - each start-up refusal, by reason;
  - each database error, by SQLite result code;
  - every 600 000 ms at `info`, one line of totals: connections open, subscriptions open, blobs stored, blobs purged, refusals per error code, closes per status, database bytes.

  A configuration error, which comes before any level is known, is the one message `main.rs` writes to standard error directly, allowing `clippy::print_stderr` there with a reason. An event at `debug` or `trace` MAY name a channel only by `short_id`, the 8 lowercase hex characters of its first 4 bytes. No event may carry any of: a `server_id`, a `client_ref`, an IP address (listener addresses included), an `X-Forwarded-For` value, `pk_ch`, `sig`, a nonce, blob bytes or SQL text. No `log` logger is installed, `axum` is built without its `tracing` feature, and no SQLite trace hook is set (spec 032-storage-ttl R12).
- R5 The test of R11 MUST install an in-memory `tracing` subscriber at `trace` level as the global default of its process, before the server starts, and check the captured output at the end of the run. It MUST assert that the captured output contains none of `K_ch`, `sk_u`, `sk_ch`, `K_msg`, `K_hdr` or any `mk` of the run, in lowercase hex or in base64. It MUST also assert that the output contains no full `channel_id`, `server_id` or `client_ref`, and no IP address (`docs/spec.md` §6 "Operation", §8 "Logging").
- R6 The same test MUST assert that every `channel_id` and every `pk` that reaches the captured output appears only as its `short_id` (AGENTS 19).

**Shutdown, exit codes and crashes**

- R7 When its shutdown future resolves (SIGTERM or SIGINT in the binary), the server MUST, in order:
  1. stop accepting connections, stop reading frames and stop every backlog stream;
  2. await `Writer::finish` of spec 032, which stores and answers every request already queued, runs `PRAGMA wal_checkpoint(TRUNCATE)` on the writer's connection and closes the database;
  3. queue a close with status 1001 on every connection, after the answers of step 2, wait at most 2 000 ms for the closes to be written, and then drop every TCP connection still open, which is not a failure;
  4. stop the deadline task and the listeners;
  5. return `Outcome::Stopped`.

  All of this MUST happen within 10 000 ms of real time. Past that, it MUST return `Outcome::Fatal`.
- R8 The binary's exit code MUST be:
  - 2 for a configuration error (R1);
  - 3 when the database is refused at start-up (spec 032-storage-ttl R3);
  - 1 for `Outcome::Fatal` and any other fatal error, a listener that cannot bind included;
  - 0 only for `Outcome::Stopped`.
- R9 A blob whose `ack` was sent MUST still be served in the backlog after the server process is killed with SIGKILL and started again on the same file.

**Entry point and exit test**

- R10 `crates/server/src/lib.rs` MUST expose the entry points `bind(settings, clock)`, which opens the database and binds the listeners (as `std::net::TcpListener`s set non-blocking, converted with `tokio::net::TcpListener::from_std` inside `run`) and returns a `Bound` whose `local_addrs()` reports the bound addresses, and `Bound::run(shutdown)`, which returns an `Outcome` and never exits the process. `Settings` with `from_env`, `ConfigError`, `StartError` with its `StartReason` (`Database` with its `DbCause`, or `Bind`), `Outcome`, `Clock`, `SystemClock` and `log::init` MUST also be `pub`, and `ManualClock` MUST be `pub` only under the feature `test-support`, like every test hook, which is otherwise compiled only under `cfg(test)`. `main.rs` MUST only read the environment, install the subscriber, wire the signals to `shutdown` and map the result to the exit code of R8. Everything else stays `pub(crate)`. This spec MUST amend spec 027-core-api R16 to name these items as the only `pub` items of `server`.
- R11 `crates/server/tests/phase3_exit.rs` MUST start the server with `bind` and `run`, on `127.0.0.1` port 0, a temporary database and a `ManualClock` whose wall reading is also the devices' `now`; every advance moves both of its readings together. It then runs two `Device`s of spec 027-core-api over `DataDir`s in temporary directories. The test itself plays the client of spec 027 R11: it opens a WebSocket to the server's current `local_addrs()` for each planned connection (plain `ws://`, because TLS belongs to the reverse proxy; the plan's port is not used), passes frames both ways, reopens with no backoff every socket that closes while its plan `id` is in the plan, and closes and reopens on `Event::Reconnect`. It advances the clock by 1 000 ms and ticks only after every queued frame has been written and read and at least 100 ms of real time have passed since the previous advance. A socket that fails to open is retried at the next tick. The run goes as follows:
  1. Device A creates a channel with TTL 86 400 on `wss://127.0.0.1`, which is also the server's `PRIVATECHAT_URLS`.
  2. Device B imports its QR.
  3. Each device sends 300 messages, one every 3 000 ms.
  4. B's socket is dropped after its 100th message.
  5. After the 200th message, the server is stopped through its shutdown future; once `run` has returned `Outcome::Stopped`, it is started again with `bind` (same file, same `ManualClock`, a new port) and `run`, and only then are sockets reopened.

  The test MUST end with:
  - every message delivered exactly once to the other device;
  - a `Delivered` event for each message on its sender;
  - no error;
  - no row left in the table after the clock moves 86 460 000 ms on in one step, the purge being awaited by polling for up to 5 s of real time.

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
| `PRIVATECHAT_ONION_MAX_CONNECTIONS` | 1 024 | 1..=1 000 000 | spec 033 R10 |
| `PRIVATECHAT_MAX_UNAUTH_CONNECTIONS` | 1 024 | 1..=1 000 000 | spec 033 R10 |
| `PRIVATECHAT_CHANNEL_PUBLISH_PER_MIN` | 120 | 1..=100 000 | spec 033 R6 |
| `PRIVATECHAT_CHANNEL_BYTES_PER_MIN` | 4 194 304 | 64 673..=2^40 | spec 033 R6 |
| `PRIVATECHAT_CHANNEL_MAX_BLOBS` | 20 000 | 1..=10 000 000 | spec 033 R7 |
| `PRIVATECHAT_CHANNEL_MAX_BYTES` | 67 108 864 | 64 673..=2^40 | spec 033 R7 |
| `PRIVATECHAT_IP_CONNECTIONS` | 64 | 1..=100 000 | spec 033 R8 |
| `PRIVATECHAT_IP_UNAUTH_CONNECTIONS` | 20 | 1..=10 000 | spec 033 R8 |
| `PRIVATECHAT_IP_NEW_PER_MIN` | 60 | 1..=100 000 | spec 033 R8 |
| `PRIVATECHAT_IP_BYTES_PER_MIN` | 8 388 608 | 64 673..=2^40 | spec 033 R12 |
| `PRIVATECHAT_IP48_CONNECTIONS` | 256 | 1..=1 000 000 | spec 033 R8 |
| `PRIVATECHAT_IP48_UNAUTH_CONNECTIONS` | 80 | 1..=1 000 000 | spec 033 R8 |
| `PRIVATECHAT_IP48_SUBNETS` | 256 | 1..=65 536 | spec 033 R8 |
| `PRIVATECHAT_IP48_BYTES_PER_MIN` | 134 217 728 | 64 673..=2^40 | spec 033 R12 |
| `PRIVATECHAT_ONION_BYTES_PER_MIN` | 33 554 432 | 64 673..=2^40 | spec 033 R12 |
| `PRIVATECHAT_LOG` | `warn` | `error`, `warn`, `info`, `debug`, `trace` | R4 |

Any of the following gives exit code 2 (R1): a value out of range, a required variable absent, a name with the `PRIVATECHAT_` prefix that is not in the table, or a name or value that is not UTF-8.

| Other input | Range | Out of range |
| --- | --- | --- |
| `X-Forwarded-For` from a trusted peer | a list of IP addresses separated by `,` and optional spaces, ≤ 8 KiB in all headers | HTTP 400 |
| Shutdown | ≤ 10 000 ms of real time after the future resolves | `Outcome::Fatal`, exit code 1 |

## Interface

```
crates/server/src/lib.rs                  bind, Bound, Settings, ConfigError, StartError, StartReason, DbCause, Outcome, Clock, SystemClock, ManualClock, log::init (R10)
crates/server/src/main.rs                 the environment, the subscriber, the signals and the exit codes only (R4, R8)
crates/server/src/config.rs               Settings::from_env (R1)
crates/server/src/client_addr.rs          the address of R3, CIDR matching with std::net only
crates/server/src/log.rs                  log::init, short_id and the totals line (R4)
crates/server/src/tests/ops.rs            s035_* unit tests
crates/server/tests/phase3_exit.rs        R11, with R5 and R6 checked over its captured output
crates/server/tests/s035_log.rs           T04, in a process of its own
crates/server/tests/s035_process.rs       R8 and R9 over the built binary (CARGO_BIN_EXE_privatechat-server)
```

```rust
pub struct Settings { /* hosts, listeners, trusted proxies, db, max_db_bytes, ChannelLimits, ConnectionLimits, log level */ }
impl Settings { pub fn from_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Result<Settings, ConfigError>; }
pub enum ConfigError { /* the variable's name, never its value */ }
pub struct StartError { pub reason: StartReason }
pub enum StartReason { Database(DbCause), Bind }
pub enum DbCause { UserVersion, JournalMode, AutoVacuum, Open }
pub enum Outcome { Stopped, Fatal }
pub fn bind(settings: Settings, clock: Arc<dyn Clock>) -> Result<Bound, StartError>;
pub struct Bound { /* database, writer, listeners */ }
impl Bound {
    pub fn local_addrs(&self) -> Vec<SocketAddr>;
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) -> Outcome;
}
pub mod log { pub fn init(level: Level); }   // fmt to stderr, no colour, `with_target(false)`

pub(crate) struct IpNet { addr: IpAddr, prefix: u8 }   // hand-written, no crate
pub(crate) fn client_addr(peer: IpAddr, forwarded: &[&str], trusted: &[IpNet]) -> Result<IpAddr, BadForwarded>;
pub(crate) fn short_id(bytes: &[u8]) -> String;   // 8 lowercase hex characters of the first 4 bytes
```

`from_env` takes the variables as an iterator, so that tests need not touch the process environment. `bind` returns `StartError` for the refusals of spec 032 R3 (`Database`) and for a listener that cannot bind (`Bind`). Each integration test file is a process of its own, so R5's global subscriber sees every thread of the server (the runtime's workers and the writer) and nothing from another test.

Dependencies added, each justified in its pull request (AGENTS 8):
- `tracing` (`default-features = false`, feature `std`);
- `tracing-subscriber` (`default-features = false`, features `fmt` and `std`).

Dev-dependencies for R11:
- `privatechat-core` with `test-support`;
- `privatechat-store`;
- `privatechat-server` itself with `test-support`, for `ManualClock`;
- `futures-util` (as in spec 030) for the harness's socket, and `log` for T04.

## Security

- The log is the easiest place for metadata to leak and the first place a seizure looks. R4 lists what may be logged, and anything not listed is forbidden. R5 and R6 check the rule mechanically over a full run.
- R3 trusts `X-Forwarded-For` only from the operator's own proxy. Otherwise any client could write a fake address into the header and dodge the per-IP limits of spec 033. The address is used for those limits only, and is never logged (R4) or stored (spec 033 R9).
- The onion listener (R2) must not be reachable from outside the host or the container network. Otherwise anyone could skip the per-IP limits by connecting to it directly. Spec 034-docker binds it to an internal network only.
- R1 refuses to start on any doubt rather than run with a default the operator did not intend. An unknown `PRIVATECHAT_` name is most often a typo in a quota.
- R7 answers every request already in the writer's queue, so a stop loses no acknowledged blob. A blob whose frame was still in flight gets no `ack`, and its client republishes it after reconnecting (spec 021-channel-session R8).
- The configured URLs are public: they are in every config of the server's channels. The start-up line logs only how many there are, so that a log line does not tie the server to its onion name.

## Public API changes

None in `core`. Spec 027-core-api R16 names the `pub` items of `server` (R10). At acceptance:
- `docs/spec.md` §6 "Operation" gains the environment variables, the onion listener and the exit codes. §8 "Logging" and AGENTS 19 point to this spec for the log test (already done when spec 100 was folded in).
- The `.github/CONTRIBUTING.md` section "Running the CI locally" gains `cargo test -p privatechat-server --all-features`.

## Test cases

- T01 (covers R1): `s035_t01_r01_configuration`:
  - the defaults apply with only `PRIVATECHAT_URLS` set;
  - `PRIVATECHAT_URLS` absent → `ConfigError`;
  - `PRIVATECHAT_MAX_CONECTIONS` (misspelt) → `ConfigError` whose message names the variable;
  - `PRIVATECHAT_CHANNEL_MAX_BYTES=100` → `ConfigError`;
  - nine URLs → `ConfigError`;
  - `wss://a.org,ws://<56>.onion` → two hosts;
  - `wss://a.org,wss://a.org:9001` → `ConfigError` (same host);
  - a `PRIVATECHAT_LOG` value that is not UTF-8 → `ConfigError`, and one on an unrelated variable → ignored;
  - no value ever appears in a message.
- T02 (covers R2): `s035_t02_r02_two_listeners`:
  - both listeners answer the upgrade;
  - a connection on the onion listener with `X-Forwarded-For` set → no address in the IP table;
  - `PRIVATECHAT_ONION_LISTEN` equal to `PRIVATECHAT_LISTEN` → `ConfigError`.
- T03 (covers R3): `s035_t03_r03_client_address`:
  - an untrusted peer with a header → the peer's address;
  - a trusted peer with `1.2.3.4, 10.0.0.2`, where `10.0.0.0/8` is trusted → `1.2.3.4`;
  - two headers are joined in order;
  - all entries trusted → the leftmost;
  - `not-an-ip` from a trusted peer → 400, no upgrade;
  - an IPv6 peer inside a trusted `/64`.
- T04 (covers R4): `s035_t04_r04_log_events`, in its own test process:
  - with a capture at `info`, over a short run with a manual clock → the start line (ports, no address), one totals line per 600 000 ms, and the stop line, and nothing else;
  - no captured line at `warn` or `error` in a clean run;
  - `log::max_level()` is `LevelFilter::Off` (`log` as a dev-dependency), so no `log` implementation is registered;
  - a `debug` event about a subscription carries `short_id` of its channel;
  - a CI step `s035_t04_r04_no_log_crate` checks that `cargo tree -e normal,build,features -p privatechat-server` shows `axum` without `tracing`.
- T05 (covers R5): `s035_t05_r05_no_secret_reaches_the_log`, at the end of the run of R11: the captured output, captured with `with_target(false)` as `log::init` writes it, contains none of the listed secrets in hex or base64, no full `channel_id`, `server_id` or `client_ref`, and no token that parses as an IP address, a token being a run between whitespace and `=,;"'()[]{}`, tried as it is and with a trailing `:port` removed.
- T06 (covers R6): `s035_t06_r06_identifiers_are_truncated`:
  - every 8-hex token that matches the start of a `channel_id` or `pk` of the run is followed by no further hex of it;
  - a `debug` event built with a `channel_id` shows exactly its `short_id`.
- T07 (covers R7): `s035_t07_r07_graceful_shutdown`, in process:
  - with 50 requests queued in a writer paused by a test hook, resolving `shutdown` → all 50 are stored and acknowledged, then every client sees close 1001, the `-wal` file is empty or absent, and `run` returns `Stopped` within 10 000 ms;
  - a client whose socket writes are paused by the `cfg(test)` hook of spec 030 → its TCP connection dropped 2 000 ms after the close was queued, and still `Stopped`;
  - a writer hung by a test hook → `Fatal` after 10 000 ms.
- T08 (covers R8): `s035_t08_r08_exit_codes`, over the binary:
  - SIGTERM, sent with `Command::new("kill").args(["-TERM", pid])` to a binary started with `PRIVATECHAT_URLS=wss://127.0.0.1`, `PRIVATECHAT_DB` in a temporary directory, `PRIVATECHAT_LISTEN=127.0.0.1:0` and `PRIVATECHAT_LOG=info`, once its start line has given its port and it accepts there → 0;
  - a configuration error → 2;
  - a database with `user_version` 2 → 3;
  - a port already bound → 1.
- T09 (covers R9): `s035_t09_r09_ack_survives_kill`: the binary acknowledges a publish and is killed with SIGKILL; a new process on the same file serves that blob in the backlog.
- T10 (covers R10): `s035_t10_r10_pub_items`: `crates/server/tests/api_surface.rs` coerces `bind`, `Settings::from_env`, `Bound::local_addrs` and `log::init` to function pointers of their exact types, and pins `Bound::run` with a compile-only call that awaits it with concrete arguments and assigns the result to an `Outcome`; a CI step builds the crate in release with no feature and checks with `cargo tree -e normal,build,features` that `test-support` is not enabled and no `ManualClock` is in scope.
- T11 (covers R11): `s035_t11_r11_phase3_exit`: the run of R11 with its assertions. Its duration on the CI runner is recorded in the pull request.

## Vectors

None: no format. The run of R11 uses the vectors of the specs it exercises only through their code.

## Acceptance criterion

`cargo test -p privatechat-server --all-features s035_` green, `phase3_exit.rs` included; clippy, `cargo deny --all-features check` and `scripts/doc_lint.sh` green. With specs 030–034 `implemented`, this closes the automatable part of the phase 3 exit criterion (`docs/spec.md` §10). `docker compose up` and `deploy/README.md` are spec 034-docker's.

## Out of scope

- The reverse proxy, TLS, the onion service configuration and the image (spec 034-docker).
- A metrics endpoint, a health endpoint and hot reloading: none in v1. The totals line is the only telemetry, and a configuration change means a restart.
- The clients' log level and subscriber (specs 050–052).

## Open questions

None.

## History

- 2026-09-25 draft; takes over the log test of spec 100 and deletes that file (`docs/audit-log.md`, "Phase 3 drafts", P3)
- 2026-09-26 amended by spec 041-desktop-bridge R18 during audit L round 2 (`docs/audit-log.md`): the start line names its port fields
- 2026-09-25 revised after audit K round 6 (`docs/audit-log.md`): the four `ip48_` variables; backlog streams stopped at shutdown; T08's environment
- 2026-09-25 revised after audit K round 5 (`docs/audit-log.md`): the closed list of events is for `info` and above; the shutdown order matches `Writer::finish`; T07 on the write-pause hook
- 2026-09-25 revised after audit K round 4 (`docs/audit-log.md`): R5 worded as an absence; the writer's stop through `Writer::finish`; `DbCause`
- 2026-09-25 revised after audit K round 3 (`docs/audit-log.md`): `bind` takes the clock and `run` only the shutdown; `StartReason` listed; both clock readings move together, the final move in one step; the harness waits for `Stopped` before rebinding; T04, T05, T07, T08 and T10 made implementable
- 2026-09-25 revised after audit K round 2 (`docs/audit-log.md`): `bind` and `Bound::run`, so the test learns the port; `main` installs the subscriber; the log checks inside the exit run; a bounded close at shutdown; the harness's reconnect and clock pacing; `StartError`, `ConfigError` and `SystemClock` `pub`; test hooks gated; the ingest-budget variables; `kill -TERM`
- 2026-09-25 revised after audit K round 1 (`docs/audit-log.md`): a library entry point that returns instead of exiting, so the exit and shutdown tests run in process; the log tests in a process of their own; listener ports, not addresses, in the start line; the crash test moved here from spec 032; `vars_os`; the per-listener and per-IP connection variables; spec 100's lint dropped
