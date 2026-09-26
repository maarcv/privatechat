# Feature specs

One spec per feature, written with `TEMPLATE.md` **before** the code and accepted by a human before implementing (AGENTS "Per-feature flow"). The canonical list of specs per phase is `docs/spec.md` §10; this index only records the ones that already exist as a file and their state, and `scripts/doc_lint.sh` checks that they match.

States: `draft` · `in review` · `accepted` · `implemented`.

## Index

| # | Spec | Phase | Status |
| --- | --- | --- | --- |
| 000 | 000-repo-layout | 0 | implemented |
| 001 | 001-ci | 0 | implemented |
| 002 | 002-adr-log | 0 | implemented |
| 003 | 003-doc-lint | 0 | implemented |
| 010 | 010-primitives-wrapper | 1 | implemented |
| 011 | 011-config-format | 1 | in review |
| 012 | 012-message-keys | 1 | in review |
| 013 | 013-wire-message | 1 | in review |
| 014 | 014-fingerprint | 1 | in review |
| 015 | 015-test-vectors | 1 | in review |
| 016 | 016-fuzz-harness | 1 | in review |
| 017 | 017-record-encoding | 1 | in review |
| 020 | 020-store-files | 2 | draft |
| 021 | 021-channel-session | 2 | draft |
| 022 | 022-peers-tofu | 2 | draft |
| 023 | 023-ttl-purge | 2 | draft |
| 024 | 024-key-retired | 2 | draft |
| 025 | 025-identity-regen | 2 | draft |
| 026 | 026-peer-limits | 2 | draft |
| 027 | 027-core-api | 2 | draft |
| 028 | 028-session-sans-io | 2 | draft |
| 030 | 030-ws-protocol | 3 | draft |
| 031 | 031-auth-channel-signature | 3 | draft |
| 032 | 032-storage-ttl | 3 | draft |
| 033 | 033-rate-limit-quotas | 3 | draft |
| 034 | 034-docker | 3 | draft |
| 035 | 035-server-ops | 3 | draft |
| 040 | 040-uniffi | 4 | draft |
| 041 | 041-desktop-bridge | 4 | draft |
| 053 | 053-device-security | 5 | draft |
| 054 | 054-qr-invite | 5 | draft |
| 055 | 055-verify-ui | 5 | draft |

Phase 0 was bootstrapped with implementation and review in parallel; from spec 010 on, acceptance precedes code.
