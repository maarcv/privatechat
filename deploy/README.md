# Deploy your own server

Phase 3, spec 034-docker and 035-server-ops. Reference deployment for `crates/server/`:
`docker-compose.yml`, `Caddyfile` (or `nginx.conf`) for TLS, and `torrc` for an optional
`.onion` service.

The server is a blind mailbox: one binary, one SQLite table, no secrets, no user accounts.
Anyone can run one; each channel picks its server when it is created (ADR 0022). Operating a
server means seeing the metadata described in `docs/threat-model.md` ("Honest-but-curious
server"), and nothing else.
