# ADR 0031 — Pad the config record so every `.chatcfg` file has the same size

Date: 2026-09-24 · Status: accepted

## Context
The `.chatcfg` file of `docs/spec.md` §5 is 45 bytes of header, 16 of the `secretbox` tag and the config record, so its length gives away the exact length of the record, and with it `len(server_url) + len(suggested_name)`. The file is considered exposed the moment it is sent, so whoever sees it pass by mail or messaging learns that sum, which can single out a self-hosted server or narrow down the channel name. Audit H (`docs/audit-log.md`, H8) raised it; nothing is frozen yet, so the format can still change without a new `config_version`.

## Decision
The record is padded with `sodium_pad` to a block of 1 024 bytes before it is sealed, so every `.chatcfg` file of `config_version = 1` is exactly 1 085 bytes.

## Alternatives considered
- Documenting the leak in §5: cheap, but every invitation would keep leaking.
- A block of 512 bytes: the record limit is 512 bytes and `sodium_pad` always adds at least one byte, so a record at the limit would pad to 1 024 and the files would again have two sizes.

## Consequences
- The file size says nothing about the channel. Its length is one fixed value, which also simplifies the length check.
- 1 085 bytes instead of 61 to 573; irrelevant for every medium the file travels by.
- A padding error after the box opens is a non-conforming writer and is `BadConfig`.
- Affected specs: 011-config-format.
