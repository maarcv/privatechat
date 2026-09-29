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
| 011 | 011-config-format | 1 | implemented |
| 012 | 012-message-keys | 1 | accepted |
| 013 | 013-wire-message | 1 | accepted |
| 014 | 014-fingerprint | 1 | accepted |
| 015 | 015-test-vectors | 1 | implemented |
| 016 | 016-fuzz-harness | 1 | accepted |
| 017 | 017-record-encoding | 1 | implemented |
| 020 | 020-store-files | 2 | accepted |
| 021 | 021-channel-session | 2 | accepted |
| 022 | 022-peers-tofu | 2 | accepted |
| 023 | 023-ttl-purge | 2 | accepted |
| 024 | 024-key-retired | 2 | accepted |
| 025 | 025-identity-regen | 2 | accepted |
| 026 | 026-peer-limits | 2 | accepted |
| 027 | 027-core-api | 2 | accepted |
| 028 | 028-session-sans-io | 2 | accepted |
| 030 | 030-ws-protocol | 3 | accepted |
| 031 | 031-auth-channel-signature | 3 | accepted |
| 032 | 032-storage-ttl | 3 | accepted |
| 033 | 033-rate-limit-quotas | 3 | accepted |
| 034 | 034-docker | 3 | accepted |
| 035 | 035-server-ops | 3 | accepted |
| 040 | 040-uniffi | 4 | accepted |
| 041 | 041-desktop-bridge | 4 | accepted |
| 042 | 042-connection-host | 4 | accepted |
| 050 | 050-desktop-mvp | 5 | accepted |
| 051 | 051-android-mvp | 5 | accepted |
| 052 | 052-ios-mvp | 5 | accepted |
| 053 | 053-device-security | 5 | accepted |
| 054 | 054-qr-invite | 5 | accepted |
| 055 | 055-verify-ui | 5 | accepted |
| 056 | 056-chat-screens | 5 | accepted |
| 060 | 060-reproducible-builds | 6 | accepted |
| 061 | 061-threat-review | 6 | accepted |
| 062 | 062-security-docs | 6 | accepted |
| 063 | 063-beta | 6 | accepted |
| 064 | 064-public-release | 6 | accepted |
| 065 | 065-release-maintenance | 6 | accepted |
| 066 | 066-public-server | 6 | accepted |

Phase 0 was bootstrapped with implementation and review in parallel; from spec 010 on, acceptance precedes code.
