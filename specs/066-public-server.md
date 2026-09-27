# 066 — The project's public server

Status: draft
Phase: 6
Related ADRs: 0014, 0022, 0038
Depends on: 034-docker, 035-server-ops, 060-reproducible-builds, 062-security-docs
Blocks: 063-beta, 064-public-release, 065-release-maintenance
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every app ships with `DEFAULT_SERVER_URL`, the project's own server (spec 000-repo-layout R4, `docs/spec.md` §8 "App settings"). New channels go there unless their creator picks another server (ADR 0022). Spec 034-docker says how anyone deploys a server, and spec 035-server-ops how it is configured and what it logs. No spec says how the project runs its own server, yet spec 063-beta R1 needs it running, the privacy policy of spec 062-security-docs R2 makes promises about it (its snapshots, its provider's logs, its data controller), and `.github/SECURITY.md` promises that a flaw affecting it is "fixed and redeployed before publication". The coverage review of audit P found this gap, and the human reviewer decided that it is a spec of its own (`docs/audit-log.md`, "Audit P", P-Q1).

This spec adds no server behaviour. It turns the reference deployment into the project's running service and makes the promises other documents make about that service checkable.

**In plain words.** The project rents one machine, in a country the owner chooses, and runs on it the server that a signed release built, checked against the release's signed list of fingerprints, with the reference setup of spec 034. Its disk is encrypted, it is never backed up and never snapshotted, and Caddy renews its certificate by itself. Once an hour, a check run from GitHub opens a connection and reads the server's greeting, and does nothing else, so the check learns nothing about anyone. When a release fixes something in the server, the machine is updated within a week, and before the fix is announced if it is a security fix. A public page says what the operator could hand over if a court asked: only encrypted blobs until they expire; and that a court could force the operator to start recording addresses from that day on.

## Requirements

- R1 `docs/public-server.md` MUST record the service: the host provider, the country of the machine and of the provider (062-R2, 066-R1), the machine's memory, disk and architecture, the last of which MUST equal the platform of the server image of spec 060-reproducible-builds R3, the memory one connection takes as measured on the machine (R3), the value of `DEFAULT_SERVER_URL`, the onion address if one is published, and a table "Deployments" with one row per deployment: date, release tag, and the image digest running. It MUST be the only document those facts are written in, the `DEFAULT_SERVER_URL` constant of spec 000-repo-layout R4 apart, which T01 compares with it; the privacy policy of spec 062-security-docs R2 and the landing's "Run your own server" page link it.
- R2 The server MUST run only the image built from a public release tag `vX.Y.Z` (spec 064-public-release) or, before it, the beta tag of spec 063-beta: the owner builds it on their own machine with the release container of spec 060-reproducible-builds R2, or takes the one `verify_release.sh` built, and carries it to the host with `docker save` and `docker load` over SSH; nothing is built on the host and no registry is used (spec 034-docker, Out of scope). Before the container starts, `scripts/check_public_server.sh <tag>` on the host MUST check the signature of that tag's `SHA256SUMS` against the release-key fingerprints held in `/etc/privatechat/release-keys`, a file the owner writes on the host from the fingerprints published out of band (spec 064-public-release R6) and never from a checkout of the repository, check that the manifest's first line names the tag's commit, and check that the loaded image's per-platform manifest digest equals the manifest's `unsigned/` image line (spec 060-reproducible-builds R3, R6); any failure leaves the running container as it was. Each deployment adds its row to R1's table in the same change.
- R3 The configuration MUST be `deploy/public/env`, committed, holding no secret, read as the `.env` of spec 034-docker R2: `SERVER_DOMAIN` and `PRIVATECHAT_URLS` naming `DEFAULT_SERVER_URL` (and the onion URL if published), the log level `warn` (`docs/spec.md` §8 "Logging"), the limits of spec 033-rate-limit-quotas at their defaults unless R1's machine cannot hold them, and `PRIVATECHAT_MAX_DB_BYTES` at most 80 % of the disk's free space recorded in R1. The number of connections the caps of spec 033 allow, times the memory one connection takes as measured on the machine with Caddy in front of it and each connection's send queue full (spec 030-ws-protocol's bound of 8.3 MiB is the server's buffers alone), MUST be at most 70 % of the machine's memory, both figures recorded in R1; otherwise the caps are lowered in this file.
- R4 The machine MUST: encrypt its disk at rest; take no snapshot of the volume `data`, or keep one for at most 60 000 ms (spec 034-docker R7); back up nothing of `data`; publish only 443/tcp (spec 034-docker R6); keep the host's own logs (SSH, the kernel, Docker's `local` driver of spec 034 R2) free of client addresses, with the host firewall logging nothing; sync its clock with an authenticated source that slews (spec 032-storage-ttl, Security); and be administered only over SSH with keys on a hardware token, the owner's alone. The provider's own network logs are outside the operator's reach and stated in the privacy policy (spec 062-security-docs R2).
- R5 TLS MUST be served by the Caddy of spec 034-docker R3, which obtains and renews the certificate itself (ACME), with TLS 1.3 only.
- R6 `.github/workflows/probe.yml` MUST, once every 3 600 s and by hand, build and run `crates/server/examples/probe.rs` against `DEFAULT_SERVER_URL`: it opens one connection, reads `hello`, checks that `proto_versions` holds 1 and that the certificate is valid for 7 days or more, and closes. It sends no `subscribe`, no `publish` and no identifier, and the workflow has `permissions: contents: read` and no secret. A failed run notifies the owner through GitHub's own failure mail; nothing else monitors the server, and the server keeps no metrics endpoint (spec 035-server-ops).
- R7 When a release changes a path the server is built from (`crates/server/`, `crates/core/`, `deploy/`, the lock files), the server MUST be redeployed from it within 7 days of the release; when the release fixes a vulnerability that affects the server (`.github/SECURITY.md`), before its disclosure. The row of R1's table records it.
- R8 A public page "Requests from authorities" (`/{lang}/legal/`, a content entry under `landing/src/content/legal/` with a `source` of `§2`, spec 062-security-docs R4) MUST state: what the operator holds and could hand over (the blobs and their metadata until expiry, as the privacy policy lists them; no address, channel or message in any log; addresses in memory only, spec 033-rate-limit-quotas R9); what it cannot hand over (no key, no content, no member list, no account); that an order can compel it to start recording addresses and times from the order onwards, which the protocol cannot prevent (`docs/spec.md` §2, row "Seized or coerced operator"), and that Tor or a self-hosted server is the answer; that only orders binding in the jurisdiction of R1 are answered; and that the number of orders received is published every year on the date `docs/public-server.md` names, where the law allows, and that a year whose entry is missing on that date should be read as an order the operator may not speak of. The privacy policy of spec 062-security-docs R2 links it. Its translations follow spec 062-security-docs R5.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Image | digest equal to the `unsigned/` line of a signed `SHA256SUMS` | not started |
| `PRIVATECHAT_MAX_DB_BYTES` | ≤ 80 % of the free disk recorded in R1 | the check fails |
| Connections allowed by the caps | × the measured memory per connection ≤ 70 % of the machine's memory | the check fails |
| Volume snapshots | none, or kept ≤ 60 000 ms | not allowed |
| Redeploy after a server-affecting release | ≤ 7 days; before disclosure for a security fix | the SECURITY.md promise is broken |
| Probe | every 3 600 s; certificate valid ≥ 7 days | the run fails and mails the owner |

## Interface

```
docs/public-server.md                       R1: the service's facts, the "Deployments" table, the yearly count of orders (R8)
deploy/public/env                           R3: the public server's configuration, no secret
scripts/check_public_server.sh              R2: check the signature by the host's fingerprints, the commit and the loaded image's digest
/etc/privatechat/release-keys                R2: on the host, written by the owner, never from the repository
crates/server/examples/probe.rs             R6: hello-only probe (dev-dependencies only)
.github/workflows/probe.yml                 R6
landing/src/content/legal/                  R8: "Requests from authorities", five languages
scripts/doc_lint.py                         check_s066_* (R1, R3, R7, R8)
```

**PR slices** (AGENTS 14): (a) the record, the configuration and its checks (R1, R3); (b) the deploy script and the probe (R2, R5, R6); (c) the legal page (R8); the machine itself (R4) and the first deployment are the owner's, recorded in (a).

## Security

- The operator runs only an image whose digest a signed release names, checked against fingerprints the repository cannot change (R2), so a stolen GitHub account cannot get its image run. Nobody outside can see which image the machine runs: the `hello` names no build, and a rebuild proves only what the tag builds. Which code runs on the public server rests on the operator's word: a documented residual.
- The probe proves availability and certificate health and learns nothing: a `hello` is the same for everyone (R6). No third-party monitoring service sees the server.
- The TTL is true on disk only if no copy outlives it: no snapshot, no backup, an encrypted disk (R4, spec 032-storage-ttl Security).
- The hosting provider sees every client's address and time at the network level (netflow), which the operator cannot turn off: a documented residual (`docs/spec.md` §2, row "Server's hosting or network provider").
- An order can compel the operator to log addresses from the order onwards, and a gag order can stop the operator from saying so, so the yearly count of R8 may be incomplete: a documented residual (`docs/spec.md` §2, row "Seized or coerced operator").
- Between a server-affecting release and its redeploy, the public server runs the previous version for up to 7 days (R7): a documented residual.
- GitHub disables a scheduled workflow after 60 days without activity in the repository, and runs scheduled workflows late when it is busy, so the probe can stop or lag unseen; the row of spec 065-release-maintenance R4 bounds the first: a documented residual.
- The owner is the single operator: a lost token or an absent owner stops redeploys, and the probe keeps failing visibly until someone acts: a documented residual.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s066_t01_r01_record`: `docs/public-server.md` names a provider, the countries, memory, disk, an architecture equal to the server image's platform of spec 060-reproducible-builds R3, the measured memory per connection, and a `wss://` URL equal to `DEFAULT_SERVER_URL` of spec 000-repo-layout R4, and its "Deployments" table has a date, a tag of the form `vX.Y.Z` or `vX.Y.Z-beta.N` and a 64-hex digest in every row; the privacy page and the "Run your own server" page link it.
- T02 (covers R2): `s066_t02_r02_digest_check`: `check_public_server.sh` run against a fixture tag with a fixture `SHA256SUMS` and signature exits 0 when the loaded digest matches and non-zero when one byte of the manifest line differs, when the signature fails, when the manifest names another commit, and when the checkout's `.github/allowed_signers` and `docs/release-keys.md` are swapped for a fixture key that signed the manifest while `/etc/privatechat/release-keys` keeps the real one; the script reads no fingerprint from the checkout; non-automatable, each deployment's digest is the one `check_public_server.sh` printed on the host, recorded in the pull request that adds its row.
- T03 (covers R3): `check_s066_t03_r03_config`: `deploy/public/env` holds only keys spec 035-server-ops accepts plus `SERVER_DOMAIN`, the log level `warn`, a `PRIVATECHAT_URLS` naming `DEFAULT_SERVER_URL`; its `PRIVATECHAT_MAX_DB_BYTES` is ≤ 80 % of R1's disk and its connection caps × R1's measured memory per connection ≤ 70 % of R1's memory; a fixture with a larger value fails.
- T04 (covers R4): non-automatable, no named check: the owner's pull request that records the machine states each item of R4 with the provider's setting (snapshots off, disk encryption on, no backup, SSH by token keys) and holds the output of a full TCP and UDP port scan of the machine from outside (`nmap -p- -sT` and `-sU`) showing only 443/tcp open.
- T05 (covers R5): `s066_t05_r05_tls`: against the compose stack of spec 034-docker R8 run with `deploy/public/env` and a test certificate, `caddy validate` passes, a TLS 1.3 handshake succeeds and a TLS 1.2 handshake is refused.
- T06 (covers R6): `s066_t06_r06_probe`: against the compose stack of spec 034-docker R8 with Caddy and a test certificate, the probe exits 0; the server's captured frames show one connection, no `subscribe` and no `publish`; with a certificate that expires in 6 days it fails and at 8 days it passes; `probe.yml` has the hourly schedule, `contents: read` and no secret.
- T07 (covers R7): `check_s066_t07_r07_redeploy`: for every release tag whose diff from the previous one touches a path of R7, a row of R1's table has that tag and a date at most 7 days later; a fixture history without it fails.
- T08 (covers R8): `check_s066_t08_r08_legal`: the English "Requests from authorities" page names each item of R8 and cites `§2` and spec 033-rate-limit-quotas R9; `docs/public-server.md` names the yearly date, and once that date has passed in a year after the first deployment, holds that year's entry; the privacy page links it; its translations are checked by `check_s062_t05_r05_translations`.

## Vectors

None.

## Acceptance criterion

The checks of T01, T03, T07 and T08, and the CI steps of T02, T05 and T06, green. Non-automatable: the owner's record of the machine (T04) and the first deployment row, both before spec 063-beta starts.

## Out of scope

- Other operators' servers and any list of them (`docs/spec.md` §12; spec 062-security-docs, "Run your own server").
- High availability, a second machine, or a hot standby: one machine; an outage is the availability residual of `docs/spec.md` §2 "Outside the model".
- Metrics, dashboards, a status page and on-call rotations.
- Publishing the image to a registry (spec 034-docker).
- Postgres (`docs/spec.md` §12).

## Open questions

- [ ] 066-R1: the host provider and the jurisdiction of the machine and of the operator; the human owner's decision, together with 062-R2 (the data controller) and 063-R1 (`DEFAULT_SERVER_URL`).
- [ ] 066-R8: whether EU rules for electronic communications or hosting services (a number-independent interpersonal communications service under the European Electronic Communications Code, or a hosting service with points of contact under the Digital Services Act) apply to the project's server, and what they require of it; not verified here, a lawyer's call for the owner before the public release.

## History

- 2026-09-28 draft (`docs/audit-log.md`, "Audit P", P-Q1)
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): R2 the image built off the host, checked against fingerprints the host holds and never the repository, and the manifest's commit; R1 the architecture and the measured memory per connection; R3 at most 70 % of memory; R5 tested by its own TLS check; R6 fails under 7 days; R8 a fixed yearly date whose absence is a signal; which image runs is the operator's word and GitHub's 60-day disable are documented residuals; T04 a recorded port scan; T05 and T06 against the compose stack; blocks 065
