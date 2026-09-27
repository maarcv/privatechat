# 062 — Public security documentation: what it promises and what it does not

Status: draft
Phase: 6
Related ADRs: 0008, 0017, 0019, 0028, 0041
Depends on: 053-device-security, 056-chat-screens, 060-reproducible-builds, 061-threat-review
Blocks: 063-beta, 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

`docs/spec.md` §1 lists what the system promises and what it does not, and asks that the second list "must be stated clearly in the documentation". §10 closes phase 6 with "public documentation of what it promises and does not promise". The specs' Security sections hold the documented residuals, which spec 061-threat-review R2 gathers into `docs/residuals.md`. And the stores ask for a privacy policy.

The public site (`landing/`, planned in `landing/CONTENT.md`) already builds its "Promises and limits" page per language from `docs/spec.md` and `docs/threat-model.md` at build time (`landing/src/lib/docs.ts`), with the rule that every promise sits next to its limit. This spec fixes the documents that must exist before the beta, where each lives, how each is kept equal to its source, and how translations stay honest. The human reviewer decided on 2026-09-27 that a translation nobody has reviewed shows the English text for that language, and that the beta does not wait for it (`docs/audit-log.md`, "Phase 6 drafts", Q17).

**In plain words.** Before anyone outside the project uses the app, there must be plain pages that say what it protects, what it does not, which small risks remain, how to use it safely, how to run your own server, how to check that a download is genuine, and what data the project's server keeps: the encrypted messages and a few facts about them until they expire, and the addresses of connected devices, in memory only, for as long as they are connected and a minute after. These pages exist in the five languages of the app; a language whose translation nobody has checked shows the English page instead, and a check fails whenever a page says something the specification does not.

## Requirements

- R1 The public documentation MUST consist of these documents under `landing/`, each with English as the source and in the five UI languages of `docs/spec.md` §12, with the English text reviewed by the human reviewer:
  - "Promises and limits" (`/{lang}/security/`): the two lists of `docs/spec.md` §1 and the adversary table of §2;
  - "Known residual risks" (`/{lang}/security/residuals/`): every entry of `docs/residuals.md` (spec 061-threat-review R2), grouped by its audience;
  - "Using it safely" (`/{lang}/guide/`): inviting in person, verifying with the 12 words or the QR, what to do when a new key claims a known name, "Create new channel" after a leak, locking and the device PIN, and Tor with a SOCKS5 proxy;
  - "Run your own server" (`/{lang}/server/`): the content of `deploy/README.md` (spec 034-docker R7) and what the operator can see (§2, "Member who operates the self-hosted server");
  - "Check a download" (`/{lang}/verify/`): how to verify `SHA256SUMS.sig` and rebuild with `scripts/verify_release.sh` (spec 060-reproducible-builds R8), where to compare the release-key fingerprints out of band (spec 060-reproducible-builds), and the iOS, Play and macOS/Windows residuals that spec names;
  - "Privacy policy" (`/{lang}/privacy/`), with the content of R2.
  The stores' privacy URLs of specs 051-android-mvp R10 and 052-ios-mvp R10 point to the privacy policy.
- R2 The privacy policy MUST state, with each duration taken from the spec value it cites and not restated in other words:
  - the apps collect nothing, contain no analytics, advertising or crash-reporting library (spec 053-device-security R16), and send nothing but protocol frames to the servers the user chooses;
  - what the project's own server keeps: each encrypted blob with its `channel_id`, `server_id`, `received_at`, `expires_at` and size, until its expiry, at most the longest TTL of spec 011-config-format (30 days) (spec 032-storage-ttl); each connected client's address, in memory only, while it is connected and up to 60 000 ms after its last connection or publish (spec 033-rate-limit-quotas R9); and logs that carry no address, channel or message (spec 035-server-ops);
  - what lies outside the app's control: the network logs of the server's hosting provider; the operating system's own checks (Gatekeeper and notarisation on macOS, SmartScreen on Windows) and WebView2's diagnostic data on Windows; the stores' install data; and the crash logs and TestFlight feedback that Apple and Google deliver to the developer for users and testers who opted in to share them;
  - who is responsible: the data controller of the project's server, a contact address and the jurisdiction, as the human owner names them (062-R2).
- R3 Every page MUST take its normative text from `docs/` at build time, never from a copy: the "Promises and limits" page from `docs/spec.md` §1 and §2 (as `landing/src/lib/docs.ts` does), and the residuals page from `docs/residuals.md`. `.github/workflows/landing.yml` MUST also run on changes to `docs/spec.md`, `docs/threat-model.md`, `docs/residuals.md` and `README.md`, so that a change of the source rebuilds and checks the site. The Help screen of spec 056-chat-screens R18 carries §1's two lists alone; `check_s062_t03_r03_promises` in `scripts/doc_lint.py` MUST fail when the English string resources of Help on any platform differ from §1's two lists, or when the root `README.md`, which keeps its plain-words version, lacks its link to §1 as the normative list or has more bullets in a list than §1.
- R4 Every content entry of `landing/src/content/` MUST carry a `source` field, required by the Zod schema of `landing/src/content.config.ts`, that names a section of `docs/spec.md` (`§N`) or an ADR (`ADR NNNN`); the landing build fails on an entry without one. Every public page MUST follow the wording rules of `landing/CONTENT.md`: "private", never "anonymous"; every promise next to its limit. `check_s062_t04_r04_wording` MUST fail on the words of `landing/src/content/forbidden-words.json`, one list per UI language (English "anonymous", "untraceable", "military-grade", "unbreakable", and each language's equivalents, reviewed by that language's translator), in any page of that language and in the store texts of specs 051-android-mvp and 052-ios-mvp.
- R5 Every translated page, and the tester letter of spec 063-beta, MUST record the SHA-256 of the English source it translates and the name of its reviewer, a speaker of that language named in the pull request that adds it. `check_s062_t05_r05_translations` MUST fail when a translation's recorded hash differs from its English source's current one. A language whose translation of a page has no reviewer, or has gone stale, MUST show the English page for that language, with a line in that language saying the page is not translated yet (Q17); the beta does not wait for it.
- R6 Before the beta, `README.md`'s status line MUST give the phase and link the "Known residual risks" page, and `.github/SECURITY.md` MUST link "Promises and limits" and "Known residual risks" and carry the review's result (spec 061-threat-review R8). In the pull request that marks this spec `accepted`, `landing/CONTENT.md`'s route table and its "planned" list MUST name the six routes of R1, and `landing/README.md`'s tree the new content folders.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Languages | English source and the four translations of §12 | the English page shown for that language |
| A translation | its recorded English hash equals the current one, and it names its reviewer | the English page shown; the lint fails on a stale hash |
| Content entries | each with a `source` naming `§N` or `ADR NNNN` | the landing build fails |
| Forbidden words | none in a page or store text of their language | the lint fails |

## Interface

```
landing/src/content/security/, residuals/, guide/, server/, verify/, privacy/   R1, in five languages
landing/src/content/forbidden-words.json                                      R4
landing/src/content.config.ts                                                 the source field (R4)
.github/workflows/landing.yml                                                 the path triggers (R3)
scripts/doc_lint.py                                                           check_s062_* (R3–R5)
```

**PR slices** (AGENTS 14): (a) the promises and residuals pages built from `docs/`, the path triggers and the Help check (R1, R3); (b) the privacy policy (R2); (c) the guide, server and verify pages (R1); (d) the source field, the wording check and the translation record (R4, R5); (e) the README, SECURITY and landing-plan links (R6); (f) the translations.

## Security

- A user or an operator can find every accepted limit in one page, in their language (R1), taken at build time from the one list of spec 061-threat-review R2 (R3), so no limit is known only to those who read the specs, and the site cannot fall behind a spec.
- The privacy policy names what the project's own server keeps and for how long from the spec values, and what lies outside the app's reach (R2), so a user does not read "nothing is kept" where metadata and addresses are.
- The wording rules, the source field and the forbidden words in every language (R4) keep the public texts from overclaiming, which in a privacy tool is itself a risk: a user who believes they are anonymous takes risks the system does not cover.
- A translation that nobody checked, or that fell behind its English source, is never shown: the English page is (R5), so no language promises more than the reviewed text.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s062_t01_r01_pages`: the landing build produces the six routes in the five languages; non-automatable, the human reviewer's reading of the English text is recorded in the pull request.
- T02 (covers R2): `check_s062_t02_r02_privacy`: the English privacy page names each item of R2 and cites specs 011, 032, 033, 035 and 053; a duration in the page that differs from the value in its cited spec fails; with 062-R2 open, the check fails once this spec is `implemented`.
- T03 (covers R3): `check_s062_t03_r03_promises`: a word changed in §1 changes the built page with no edit under `landing/`; a Help string that differs from §1 fails; a README without the §1 link, or with an extra bullet, fails; `landing.yml` lists the four path triggers.
- T04 (covers R4): the landing build fails on a content entry without `source`; `check_s062_t04_r04_wording`: a Spanish page with "anónimo" fails, an English one with "anonymous" fails, and a store text with "untraceable" fails.
- T05 (covers R5): `check_s062_t05_r05_translations`: a Catalan page whose recorded hash differs from its English source's fails; a page with no reviewer is built as the English page with the "not translated yet" line.
- T06 (covers R6): `check_s062_t06_r06_links`: the README and `.github/SECURITY.md` hold the links of R6; once this spec is `accepted`, `landing/CONTENT.md` names the six routes.

## Vectors

None.

## Acceptance criterion

The documentation lint and the landing build green. Non-automatable: the human reviewer reads every English page; each translation shown is read by its named reviewer.

## Out of scope

- The landing's design and components (`landing/CONTENT.md` and its own work).
- Marketing and store screenshots.
- The developer documentation (`AGENTS.md`, `.github/CONTRIBUTING.md`, the specs), which already exists.
- `docs/residuals.md` itself and its check, which are spec 061-threat-review R2's.

## Open questions

- [ ] 062-R2: the data controller of the project's public server, its contact address and its jurisdiction, for the privacy policy; the human owner's decision, together with the server of 063-R1.

## History

- 2026-09-27 draft
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): the privacy policy made exact from the spec values, with metadata, the 60 s of addresses, what lies outside the app and the controller; every page built from `docs/`, with path triggers; Help checked against §1 alone; a `source` field per entry; forbidden words per language; translations tied to their English source's hash, and an unreviewed or stale one shown in English (Q17); the residuals page renamed "Known residual risks" and its list owned by spec 061; the landing plan amended at acceptance
