# 062 — Public security documentation: what it promises and what it does not

Status: draft
Phase: 6
Related ADRs: 0008, 0017, 0019, 0028, 0041
Depends on: 053-device-security, 056-chat-screens, 060-reproducible-builds, 061-threat-review
Blocks: 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

`docs/spec.md` §1 lists what the system promises and what it does not, and asks that the second list "must be stated clearly in the documentation". §10 closes phase 6 with "public documentation of what it promises and does not promise". The specs have also accumulated, in their Security sections, dozens of documented residuals: small, accepted limits that users and operators should be able to find in one place. And the stores ask for a privacy policy.

The public site (`landing/`, planned in `landing/CONTENT.md`) already has a "Promises and limits" page per language, with the rule that every promise sits next to its limit. This spec fixes the documents that must exist before the beta, where each lives, the single source of each list, and the checks that keep them from drifting apart.

**In plain words.** Before anyone outside the project uses the app, there must be plain pages that say what it protects, what it does not, what small risks remain, how to use it safely, how to run your own server, how to check that a download is genuine, and what data the project's server keeps (none beyond what it needs for a few seconds). These pages exist in the five languages of the app, and a check fails whenever one of them says something the specification does not.

## Requirements

- R1 The public documentation MUST consist of these documents, each in English as the source, and each under `landing/` in the five UI languages of `docs/spec.md` §12, with the English text reviewed by the human reviewer and every translation by a speaker of that language before the beta:
  - "Promises and limits" (`/{lang}/security/`): the two lists of `docs/spec.md` §1, word for word, and the adversary table of §2;
  - "Accepted limits" (`/{lang}/security/limits/`): every documented residual, grouped by who it concerns (users, desktop users, phone users, server operators), from `docs/residuals.md` (R2);
  - "Using it safely" (`/{lang}/guide/`): inviting in person, verifying with the 12 words or the QR, what to do when a new key claims a known name, "Create new channel" after a leak, locking and the device PIN, and Tor with a SOCKS5 proxy;
  - "Run your own server" (`/{lang}/server/`): the content of `deploy/README.md` (spec 034-docker R7) and what the operator can see (§2, "Member who operates the self-hosted server");
  - "Check a download" (`/{lang}/verify/`): how to verify `SHA256SUMS.sig` and rebuild with `scripts/verify_release.sh` (spec 060-reproducible-builds R8), the release keys of `docs/release-keys.md`, and the iOS residual;
  - "Privacy policy" (`/{lang}/privacy/`): the apps collect nothing and send nothing but messages to the servers the user chooses; what the project's own server holds and for how long (encrypted blobs until their TTL; client addresses only in memory while connected; the logs of spec 035-server-ops, which carry no address or identifier); no analytics, no crash reporting, no advertising (spec 053-device-security R16). The stores' privacy URLs of specs 051-android-mvp R10 and 052-ios-mvp R10 point to it.
- R2 `docs/residuals.md` MUST be the single source of the accepted limits: one entry per documented residual of every spec's Security section, with the spec id, the audience of R1 and one sentence in plain language, and the entries that spec 061-threat-review R6 added after the review. `docs/review/residuals.md` of spec 061-threat-review R2 is generated from it for the reviewers' frozen commit. `check_s062_t02_r02_residuals` in `scripts/doc_lint.py` MUST fail when a spec whose Security section contains "documented residual" has no entry in `docs/residuals.md`, or an entry names a spec that no longer says so.
- R3 The texts of `docs/spec.md` §1 and §2 MUST have one source: the English pages of R1 and the Help screen of spec 056-chat-screens R18 reproduce them word for word, `check_s062_t03_r03_promises` in `scripts/doc_lint.py` MUST fail on any difference between §1's two lists and the English "Promises and limits" page, and between §2's table and that page's table (spec 003-doc-lint already compares `docs/threat-model.md`). The root `README.md` keeps its plain-words version and links §1 as the normative list; the check fails when that link is missing or when the README has more bullets in a list than §1.
- R4 Every public page MUST follow the wording rules of `landing/CONTENT.md`: "private", never "anonymous"; every promise next to its limit; no claim without a source in `docs/spec.md` or an ADR, cited in the page's source file as a comment. `check_s062_t04_r04_wording` MUST fail on the words "anonymous", "untraceable", "military-grade" and "unbreakable" in any page of `landing/src/content/` and in the store texts of specs 051 and 052.
- R5 Before the beta, `README.md`'s status line MUST give the phase and link the "Accepted limits" page, and `.github/SECURITY.md` MUST link "Promises and limits" and "Accepted limits" and carry the review's result (spec 061-threat-review R8).

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Languages | English source and the four translations of §12 | a page missing in one language fails the landing build |
| Residuals | one entry per documented residual of every spec | the lint fails |
| Forbidden words | none in public pages or store texts | the lint fails |

## Interface

```
docs/residuals.md                                           R2
landing/src/content/security/, limits/, guide/, server/, verify/, privacy/   R1, in five languages
scripts/doc_lint.py                                         check_s062_* (R2–R4)
```

**PR slices** (AGENTS 14): (a) `docs/residuals.md` and its lint check (R2); (b) the promises and privacy pages with the one-source check (R1, R3); (c) the guide, server and verify pages (R1); (d) the wording check, the README and SECURITY links (R4, R5); (e) the translations.

## Security

- A user or an operator can find every accepted limit in one page, in their language (R1, R2), so no limit is only known to those who read the specs.
- One source per list, checked by the lint (R2, R3), so the site, the app's Help and the README cannot drift into promising more than the specification does.
- The wording rules and the forbidden words (R4) keep the public texts from overclaiming, which in a privacy tool is itself a risk: a user who believes they are anonymous takes risks the system does not cover.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s062_t01_r01_pages`: the landing build produces the six routes in the five languages; non-automatable, the reviews of the English text and the translations are recorded in the pull request.
- T02 (covers R2): `check_s062_t02_r02_residuals`: a fixture spec with a "documented residual" and no entry fails; an entry for a spec that no longer has one fails; the real files pass.
- T03 (covers R3): `check_s062_t03_r03_promises`: a word changed in §1 or in the English page fails the check; a README without the §1 link, or with an extra bullet, fails.
- T04 (covers R4): `check_s062_t04_r04_wording`: a page with "anonymous" fails; a page claim without a source comment fails.
- T05 (covers R5): `check_s062_t05_r05_links`: the README and `.github/SECURITY.md` hold the links of R5.

## Vectors

None.

## Acceptance criterion

The documentation lint and the landing build green. Non-automatable: the human reviewer reads every English page, and a speaker of each UI language reads its translation.

## Out of scope

- The landing's design and components (`landing/CONTENT.md` and its own work).
- Marketing and store screenshots.
- The developer documentation (`AGENTS.md`, `.github/CONTRIBUTING.md`, the specs), which already exists.

## Open questions

None.

## History

- 2026-09-27 draft
