# ADR 0009 — TTL defined in the config, enforced by server and client

Date: 2026-09-19 · Status: accepted

## Context
Messages must disappear after a time defined per channel.

## Decision
`ttl_seconds` lives in the config (60 s – 30 days). The server deletes the blobs once the TTL has passed. The client deletes the messages on its own, according to its copy of the config, without depending on the server.

## Alternatives considered
- Server only: the server is not trusted; it could retain copies and the client cannot verify it.

## Consequences
- The real deletion guarantee is the client's. The server's is hygiene and is documented as such (no message backups, `secure_delete`, `docs/spec.md` §6).
- How the server knows and enforces the TTL without anyone being able to change it: ADR 0014. The initial rule "if different TTLs arrive, the smallest wins" was withdrawn in review B (finding B5).
