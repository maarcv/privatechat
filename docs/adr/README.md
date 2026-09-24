# Architecture decision log

One decision per file, template in `TEMPLATE.md`. The documentation lint (spec 003) checks that this table, the files and the table in `docs/spec.md` §3 agree in number, title and status.

## Procedure

- An accepted ADR is not edited, except to change its status. To change a decision, a new ADR is created with `Supersedes: NNNN` and the old one moves to `Status: superseded by MMMM`.
- Numbers are sequential and are not reused.
- States: `proposed` · `accepted` · `deprecated` · `superseded by NNNN`.
- ADRs 0001–0022 were written before the repository was created and have been reviewed in four audits (`docs/audit-log.md`); that is why some contain review notes in their Context, Decision or Consequences.

## Index

| # | Title | Date | Status |
| --- | --- | --- | --- |
| 0001 | Pre-shared channel key exchanged out of band | 2026-09-19 | accepted |
| 0002 | A single AEAD (XChaCha20-Poly1305) via libsodium | 2026-09-19 | accepted |
| 0003 | Symmetric hash ratchet over the channel key | 2026-09-19 | superseded by 0013 |
| 0004 | No post-compromise security in v1 | 2026-09-19 | accepted |
| 0005 | Ed25519 signatures per message, with a key per user and per channel | 2026-09-19 | accepted |
| 0006 | TOFU: no member list in the config | 2026-09-19 | accepted |
| 0007 | Free key regeneration with no link to the old key | 2026-09-19 | accepted |
| 0008 | No member removal: a new channel is created | 2026-09-19 | accepted |
| 0009 | TTL defined in the config, enforced by server and client | 2026-09-19 | accepted |
| 0010 | Server authentication with a per-channel Ed25519 key pair | 2026-09-19 | accepted |
| 0011 | Compromise alarm | 2026-09-19 | deprecated |
| 0012 | Cryptographic and protocol core in Rust, shared by all clients | 2026-09-19 | accepted |
| 0013 | Message key derived directly from the counter | 2026-09-20 | accepted |
| 0014 | TTL bound to the `channel_id` and per-message expiry | 2026-09-20 | accepted |
| 0015 | Fixed-size binary envelope; CBOR only in the encrypted payload | 2026-09-20 | superseded by 0023 |
| 0016 | Key retirement with a `key_retired` message | 2026-09-20 | accepted |
| 0017 | No hosted web client in v1; native desktop client | 2026-09-20 | accepted |
| 0018 | Message header encrypted with the channel key | 2026-09-20 | accepted |
| 0019 | One key, one device: strictly increasing counter | 2026-09-20 | accepted |
| 0020 | Store and sans-I/O session in the Rust core | 2026-09-20 | accepted |
| 0021 | Client without a database: encrypted files with atomic commit | 2026-09-20 | accepted |
| 0022 | Exchange server per channel, fixed at creation | 2026-09-20 | accepted |
| 0023 | Fixed binary envelope and an own record encoding; no CBOR | 2026-09-24 | accepted |
| 0024 | Verify the signature before any state check, and expire by the signed send time | 2026-09-24 | superseded by 0027 |
| 0025 | Fingerprint words from 132 bits of the fingerprint, with no BIP-39 checksum | 2026-09-24 | accepted |
| 0026 | Invitation with a fixed expiry, a text QR and a canonical password | 2026-09-24 | superseded by 0028 |
| 0027 | Verify the signature before any state; a stale message changes nothing but the cursor | 2026-09-24 | accepted |
| 0028 | The export draws the file password; the invitation crosses the boundary as bytes | 2026-09-24 | accepted |
