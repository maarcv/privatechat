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
| 100 | 100-log-test | 6 | draft |

Phase 0 was bootstrapped with implementation and review in parallel; from spec 010 on, acceptance precedes code.

Spec 100 is numbered outside the phases on purpose: it holds an obligation of `docs/spec.md` §8 that no spec could carry yet, and it stays `draft` until a spec that emits logs adopts it or it is implemented on its own before phase 6 closes.
