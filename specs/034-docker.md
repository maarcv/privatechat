# 034 — Docker image and reference deployment

Status: draft
Phase: 3
Related ADRs: 0017, 0022, 0038
Depends on: 035-server-ops
Blocks: —
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Anyone may run a server, and each channel lives on the server its creator chose (ADR 0022). A server that only its authors can deploy does not honour that. `docs/spec.md` §10 closes phase 3 with a working `docker compose up` and a `deploy/README.md` titled "Deploy your own server". §6 "Operation" asks for reference configurations for Caddy and nginx (no access log, TLS 1.3 only, no session tickets) and a `torrc` that publishes the service as `.onion`. With ADR 0038 that onion service speaks plain `ws://` to the server's onion listener (spec 035-server-ops R2), and no certificate is needed for it.

This spec is the container image, the compose file, the proxy and Tor configurations, the operator's guide, and the CI job that proves they work together. It adds no server behaviour.

**In plain words.** An operator with a small machine, a domain name and Docker copies one example file, writes their domain in it and runs one command. Caddy gets a certificate by itself and passes connections to the server. The server runs as an unprivileged user in a read-only container and keeps its database in one volume. Anyone who also wants a Tor address turns on one extra service, and the guide shows how to read the address it created. The guide also says plainly what an operator can see, and that the database must not be backed up.

**PR slices** (AGENTS 14): (a) the image and the compose file (R1, R2, R6); (b) the proxy and Tor configurations (R3–R5); (c) the guide and the CI job (R7, R8).

## Requirements

- R1 `deploy/Dockerfile` MUST build the server in two stages. The builder is `rust:<version>-slim-bookworm`, the version of `rust-toolchain.toml`, pinned by digest, so that its glibc is no newer than the runtime's; it installs `make` (`apt-get install -y --no-install-recommends make`), which the vendored libsodium build of `libsodium-sys-stable` needs and the slim image lacks, and runs `cargo build --release --locked -p privatechat-server`. The runtime is `gcr.io/distroless/cc-debian12:nonroot`, pinned by digest, and holds only the binary and an empty `/data` directory owned by `65532:65532` (copied with `--chown`), declared as a volume; it runs as user 65532 with the binary as the entrypoint.
- R2 `deploy/docker-compose.yml` MUST define the services `server` and `caddy`, and `tor` under the profile `onion`, on three networks with fixed subnets: `front` (Caddy and the server, with `enable_ipv6: true` and a fixed IPv6 ULA subnet beside its IPv4 one, so that Docker forwards an IPv6 client to Caddy with its own address rather than through the IPv4 userland proxy, which would give every IPv6 client one address), `onion` (`internal: true`: Tor and the server) and `egress` (Tor's way out). The server MUST run with `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, its database on the named volume `data` mounted at `/data`, `restart: unless-stopped`, `stop_grace_period: 15s` (above the 10 s shutdown of spec 035 R7, so that Docker's SIGKILL never races the final checkpoint), and its configuration from `.env` (spec 035-server-ops), whose only non-server variable, `SERVER_DOMAIN`, has no `PRIVATECHAT_` prefix so that spec 035 R1 ignores it. Every service MUST use the `local` logging driver with `max-size: 10m` and `max-file: 3`, so that no log grows without bound on the host. `PRIVATECHAT_LISTEN` is its address on `front`, `PRIVATECHAT_ONION_LISTEN` its address on `onion`, and `PRIVATECHAT_TRUSTED_PROXIES` Caddy's address on `front`.
- R3 `deploy/Caddyfile` MUST serve only `{$SERVER_DOMAIN}`, with TLS 1.3 only, forwarding every request to the server's main listener, with no access log, and with its `http.log.error` and `http.handlers.reverse_proxy` loggers discarded, since both write the client's address. No other site or route.
- R4 `deploy/nginx.conf`, the alternative to Caddy, MUST set `ssl_protocols TLSv1.3`, `ssl_session_tickets off`, `ssl_session_cache off`, `access_log off` and `error_log /dev/null emerg` (its error lines, `crit` ones included, name the client's address). It MUST forward the WebSocket upgrade (`Upgrade` and `Connection` headers, HTTP/1.1), set `X-Forwarded-For` to `$remote_addr` (replacing any value the client sent), and set `proxy_read_timeout` to 90 s, above the 60 s that ping and pong can take (spec 033-rate-limit-quotas R4).
- R5 `deploy/tor/Dockerfile` MUST build Tor from Debian's `tor` package on `debian:bookworm-slim` pinned by digest, running as `debian-tor`, with a `HiddenServiceDir` owned by `debian-tor` with mode 0700, and `deploy/torrc` MUST publish a v3 onion service with `HiddenServiceDir` on the named volume `tor`, `HiddenServicePort 80` pointing to the server's onion listener by its fixed IP address on `onion` (Tor refuses a host name there), `SocksPort 0` and no `ControlPort`.
- R6 Only Caddy's port 443/tcp MUST be published on the host. The server's listeners and Tor MUST NOT be published, and the onion listener MUST be reachable only on the `onion` network.
- R7 `deploy/README.md`, titled "Deploy your own server", MUST cover in this order: what is needed (a host, a domain pointing to it, Docker with Compose); `.env` from `deploy/.env.example` (`SERVER_DOMAIN`, `PRIVATECHAT_URLS`); `docker compose up -d`; the `wss://` URL to enter when creating a channel; the onion service (`--profile onion`, reading the address from the `tor` volume, adding `ws://<address>.onion` to `PRIVATECHAT_URLS`, restarting the server); updating; what the operator can see and cannot see, pointing to `docs/spec.md` §1 and §2 and to `docs/threat-model.md`; no backup of the `data` volume, volume snapshots kept for at most 60 s or not taken, disk encryption at rest recommended; the log level and the limits (the table of spec 035), with the memory to plan for (about 8.3 MiB per connection at most, spec 030 Security, so 42 GiB at the default caps, or lower caps on a smaller host), with `ip_connections`, `ip_unauth_connections`, `ip_new_per_min`, `ip_bytes_per_min` and the four `ip48_` values named as the values to raise for a server with many Tor, carrier-NAT, carrier-IPv6 or office users, and `onion_bytes_per_min` and `onion_max_connections` for a busy onion service (spec 033 Security); that the per-IP limits need each client's real address, which rootless Docker and a Docker daemon with ip6tables disabled replace with one internal address, so that such hosts must not be used; time synchronisation that is authenticated and slews, never steps, the clock (spec 032 Security); stopping.
- R8 A CI job `docker` MUST, on every pull request that touches `deploy/` or `crates/server/`, build both images, check `deploy/Caddyfile` with `caddy validate`, check `deploy/nginx.conf` with `nginx -t` using a throw-away certificate and `--add-host server:<its fixed address>` so that the upstream name resolves, start the compose file with `deploy/ci.override.yml` (the server's main port published on `127.0.0.1:8080`, `caddy` given `profiles: [never]` so that only `server` starts, no Tor, `PRIVATECHAT_URLS=wss://chat.example.org`), after copying `deploy/.env.example` to `deploy/.env`,, and run `cargo run -p privatechat-server --example smoke -- ws://127.0.0.1:8080`. The smoke client MUST create a channel on `wss://chat.example.org` with a `Device` of spec 027-core-api, send one message through the container, and exit 0 only after `Event::Delivered`. The job then checks that `docker compose logs server` contains no line above `warn`.

## Limits

| Item | Value | Otherwise |
| --- | --- | --- |
| Base images | pinned by digest, the Rust version equal to `rust-toolchain.toml` | CI fails (R8 builds from the pins) |
| Ports published on the host | 443/tcp only | review rejects |
| Server container | read-only root, no capability, user 65532 | review rejects |
| `proxy_read_timeout` (nginx) | 90 s | — |
| Smoke run | ≤ 120 s | the job fails |

## Interface

```
deploy/Dockerfile               R1
deploy/docker-compose.yml       R2, R6
deploy/ci.override.yml          R8
deploy/.env.example             SERVER_DOMAIN, PRIVATECHAT_URLS, with comments
deploy/Caddyfile                R3
deploy/nginx.conf               R4
deploy/tor/Dockerfile           R5
deploy/torrc                    R5
deploy/README.md                R7
crates/server/examples/smoke.rs R8, the smoke client (dev-dependencies only)
.github/workflows/ci.yml        the job `docker`, with its steps named s034_tTT_rRR_* (R8)
```

The example is compiled only with the server's dev-dependencies (`privatechat-core` with `test-support`, `privatechat-store`, `tokio-tungstenite`, `futures-util`) and never ships in the image, which R1 builds with `-p privatechat-server` and no example.

## Security

- The container runs with no privilege, a read-only root and one writable volume. A flaw in the server gives an attacker the database, which holds only what the network already carried, and no shell (distroless).
- R6 keeps the onion listener off the host and off `front`. Only Tor can reach it, so nobody can use it to skip the per-IP limits of spec 033 (spec 035 Security).
- Caddy writes no access log by default, and R3 adds none and discards the two loggers that name clients. nginx is told `access_log off` and writes its error log nowhere. Neither proxy may log what the server itself refuses to log, and the `local` driver bounds whatever Docker keeps (R2).
- Tor's `HiddenServiceDir` holds the onion service's private key. It lives in its own volume, and the guide says to keep it (losing it changes the address, and every channel on it then points nowhere) and never to share it.
- The guide's backup rule (R7) is what makes the TTL true on disk. A daily snapshot of `data` would keep every message for as long as the snapshot is kept.
- The client never resumes a TLS session (§6, specs 050–052), so a session ticket a proxy issues is never used. nginx disables them anyway (R4). For Caddy, see the open question.

## Public API changes

None in `core`. `docs/spec.md` §9 "Server" and §11 `deploy/` already name these files. At acceptance, `docs/spec.md` §6 "Operation" says `HiddenServicePort 80` (ADR 0038) instead of 443 and names the proxies' error-log settings, and `.github/CONTRIBUTING.md` gains the commands of the job `docker`.

## Test cases

- T01 (covers R1): a CI step `s034_t01_r01_image`: the image builds; `docker run --entrypoint` with any shell fails (no shell in the image); `docker image inspect` shows user 65532; the container starts on a fresh named volume and creates `/data/messages.db`.
- T02 (covers R2): a CI step `s034_t02_r02_compose_hardening`, after copying `.env.example` to `.env`: `docker compose config` shows `read_only`, `cap_drop: ALL`, `no-new-privileges` and the `data` volume for `server`, the three networks with `onion` internal and `front` with `enable_ipv6: true`, `tor` only under the profile `onion`, and the `local` logging driver with its two limits on every service, and `stop_grace_period: 15s` on `server`.
- T03 (covers R3): a CI step `s034_t03_r03_caddy_validate`, with `SERVER_DOMAIN=chat.example.org`: `caddy validate --adapter caddyfile` passes; the adapted JSON has one route, and the TLS policy whose `sni` matches the domain has `protocol_min` `tls1.3` (Caddy always adds a catch-all policy, which is not checked), no access log, and the two loggers of R3 discarded.
- T04 (covers R4): a CI step `s034_t04_r04_nginx_test`: `nginx -t` passes with a throw-away certificate, and the file contains the five directives, the upgrade headers, `X-Forwarded-For $remote_addr` and `proxy_read_timeout 90s`.
- T05 (covers R5): a CI step `s034_t05_r05_tor_config`: the Tor image builds; `tor --verify-config -f deploy/torrc` passes inside it; the file has `HiddenServicePort 80`, `SocksPort 0` and no `ControlPort`; the service starts and writes `hostname` into its directory.
- T06 (covers R6): a CI step `s034_t06_r06_published_ports`: in `docker compose --profile onion config`, only `caddy` has `ports`, and it holds exactly `443:443/tcp`.
- T07 (covers R7): a CI step `s034_t07_r07_readme_sections`: `deploy/README.md` has the title and the eleven topics of R7 as headings, in order.
- T08 (covers R8): the job `docker`, with a step `s034_t08_r08_compose_smoke`: the smoke client exits 0 within 120 s, and the server's log has no line above `warn`.

## Vectors

None.

## Acceptance criterion

The CI job `docker` green on the pull request; a human runs `docker compose up -d` from `deploy/README.md` on a clean host with a real domain, creates a channel from the command line through the smoke client pointed at `wss://<domain>`, and records the result in the pull request. That run is the non-automatable part of the phase 3 exit criterion (`docs/spec.md` §10).

## Out of scope

- Reproducible builds and published image hashes (spec 060-reproducible-builds).
- Publishing an image to a registry, orchestration beyond Compose, high availability.
- The project's own public server and its domain (`DEFAULT_SERVER_URL`, `docs/spec.md` §12).

## Open questions

- [ ] 034-R3: Caddy's documentation, at the time of drafting, shows no Caddyfile switch that turns off TLS session tickets, and §6 asks the reference configurations for "no session tickets". Tickets a server issues matter only if a client uses them, and the clients never resume (§6). nginx turns them off (R4). Audit K round 6 found that Caddy has the switch in its JSON configuration (`apps.tls.session_tickets.disabled`) but no Caddyfile form of it. Recommendation: keep the Caddyfile for its simplicity, say in the guide that its tickets are unused, and do not ship a JSON configuration for a setting that protects nothing here.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit K round 7 (`docs/audit-log.md`): IPv6 on `front`; the real-address requirement and the onion values in the guide; `futures-util` and `log` for the smoke client
- 2026-09-25 revised after audit K round 6 (`docs/audit-log.md`): the Tor target by IP; `.env` copied in CI; `caddy` under a `never` profile in CI; T03's policy check; the open question updated
- 2026-09-25 revised after audit K round 5 (`docs/audit-log.md`): `make` in the builder
- 2026-09-25 revised after audit K round 4 (`docs/audit-log.md`): memory sizing in the guide
- 2026-09-25 revised after audit K round 2 (`docs/audit-log.md`): `stop_grace_period: 15s`; nginx's error log discarded; the NAT note
- 2026-09-25 revised after audit K round 1 (`docs/audit-log.md`): `SERVER_DOMAIN` outside the server's prefix; a bookworm builder; `/data` and the Tor directory owned by their users; the proxies' error logs and Docker's logs bounded; `nginx -t` with the upstream host; the Tor-exit note in the guide; the §6 updates listed
