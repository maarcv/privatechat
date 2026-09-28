# 062 — Public security documentation: what it promises and what it does not

Status: accepted
Phase: 6
Related ADRs: 0008, 0017, 0019, 0028, 0041
Depends on: 053-device-security, 056-chat-screens, 060-reproducible-builds, 061-threat-review
Blocks: 063-beta, 064-public-release, 066-public-server
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-28

## Context

`docs/spec.md` §1 lists what the system promises and what it does not, and asks that the second list "must be stated clearly in the documentation". §10 closes phase 6 with "public documentation of what it promises and does not promise". The specs' Security sections hold the documented residuals, which spec 061-threat-review R2 gathers into `docs/residuals.md`. And the stores ask for a privacy policy.

The public site (`landing/`, planned in `landing/CONTENT.md`) already builds its "Promises and limits" page per language from `docs/spec.md` and `docs/threat-model.md` at build time (`landing/src/lib/docs.ts`), with the rule that every promise sits next to its limit. This spec fixes the documents that must exist before the beta, where each lives, how each is kept equal to its source, and how translations stay honest. The human reviewer decided on 2026-09-27 that a translation nobody has reviewed shows the English text for that language, and that the beta does not wait for it (`docs/audit-log.md`, "Audit O", O-Q3).

**In plain words.** Before anyone outside the project uses the app, there must be plain pages that say what it protects, what it does not, which small risks remain, how to use it safely, how to run your own server, how to check that a download is genuine, and what data the project's server keeps: the encrypted messages and a few facts about them until they expire, and the addresses of connected devices, in memory only, for as long as they are connected and a minute after; and what its operator can see while it runs, even without keeping it. These pages exist in the five languages of the app; a language whose translation nobody has checked shows the English page instead, and a check fails whenever a page says something the specification does not.

## Requirements

- R1 The public documentation MUST consist of these documents under `landing/`, each with English as the source and in the five UI languages of `docs/spec.md` §12, with the English text reviewed by the human reviewer:
  - "Promises and limits" (`/{lang}/security/`): the two lists of `docs/spec.md` §1 and the adversary table of §2, and a link to the security-release feed `/security.atom` (spec 065-release-maintenance R2);
  - "Known residual risks" (`/{lang}/security/residuals/`): every entry of `docs/residuals.md` (spec 061-threat-review R2), grouped by its audience;
  - "Using it safely" (`/{lang}/guide/`): inviting in person, verifying with the 12 words or the QR, what to do when a new key claims a known name, "Create new channel" after a leak, locking and the device PIN, and Tor with a SOCKS5 proxy;
  - "Run your own server" (`/{lang}/server/`): the content of `deploy/README.md` (spec 034-docker R7); what the operator can see (§2, "Member who operates the self-hosted server"); that the project publishes no server image to a registry, so an operator builds the image from the release tag in the container of spec 060-reproducible-builds and compares its digest with the image's line of the signed `SHA256SUMS`; and that the apps carry no list of servers, a list of known community servers, if the project ever keeps one (`docs/spec.md` §12), living on this page alone; and a link to `docs/public-server.md`, the record of the project's own server (spec 066-public-server R1);
  - "Check a download" (`/{lang}/verify/`): the steps of spec 060-reproducible-builds R8 in order: first the one-line check `ssh-keygen -Y check-novalidate -n <namespace> -s SHA256SUMS.sig < SHA256SUMS`, with the namespace of the tag's suffix (`privatechat-release`, or `privatechat-rc` for an `-rc` tag), which must exit 0 and whose printed `SHA256:` fingerprint is compared with one obtained out of band, needing nothing from the repository; then the downloaded files checked against the manifest with the exact command of spec 060-reproducible-builds R8 (`grep '^[0-9a-f]\{64\}  signed/' SHA256SUMS | sed 's#  signed/#  #' | shasum -a 256 -c`), which skips the manifest's first line; then the check that the clone's commit equals the one the manifest names; only then `scripts/verify_release.sh`, and, for a public release, its Sigstore Rekor inclusion check; where the fingerprints can be compared out of band, the current and retired release keys with their `valid-before` dates, and a link to the signed rotation statement; and the residuals, iOS and macOS/Windows from spec 060-reproducible-builds R4, Google Play from spec 064-public-release R4;
  - "Privacy policy" (`/{lang}/privacy/`), with the content of R2;
  - "Requests from authorities" (`/{lang}/legal/`), with the content of spec 066-public-server R8, built from `landing/src/content/legal/`.
  The stores' privacy URLs of specs 051-android-mvp R10 and 052-ios-mvp R10 point to the privacy policy.
- R2 The privacy policy MUST state, with each duration taken from the spec value it cites and not restated in other words:
  - the apps collect nothing, contain no analytics, advertising or crash-reporting library (spec 053-device-security R16), and send nothing but protocol frames to their servers: the project's own server, which the apps name by default (`DEFAULT_SERVER_URL`, spec 000-repo-layout R4), and any server the user or a channel's creator chose instead;
  - what the project's own server keeps: each encrypted blob with its `channel_id`, `server_id`, `received_at`, `expires_at` and size, until its expiry and at most one purge interval after it (spec 032-storage-ttl R10), the longest expiry being the longest TTL of spec 011-config-format (30 days); what the hosting provider's snapshots and the disk may still hold after a purge (spec 032-storage-ttl, Security); each connected client's address, in memory only, while it is connected and up to 60 000 ms after its last connection or publish (spec 033-rate-limit-quotas R9); and logs that carry no address, channel or message (spec 035-server-ops);
  - what the project's server sees while it runs without keeping it: which addresses subscribe to which `channel_id`, and when (`docs/spec.md` §2, first row of the adversary table);
  - what lies outside the app's control: the DNS resolver, which sees the server's host name when no proxy is set; the network logs of the server's hosting provider; the access logs of the landing's host, which record the address of every visitor, those who open "Check a download" or a download included (R8); the operating system's own checks (Gatekeeper and notarisation on macOS, SmartScreen on Windows) and WebView2's diagnostic data on Windows; the stores' install data; and the crash logs and TestFlight feedback that Apple and Google deliver to the developer for users and testers who opted in to share them;
  - who is responsible: the data controller of the project's server, a contact address and the jurisdiction, as the human owner names them (062-R2), with links to `docs/public-server.md` (spec 066-public-server R1) and to the "Requests from authorities" page of R1.
- R3 Every page MUST take its normative text from `docs/` at build time, never from a copy: the "Promises and limits" page from `docs/spec.md` §1 and §2 (as `landing/src/lib/docs.ts` does), and the residuals page from `docs/residuals.md`. `.github/workflows/landing.yml` MUST also run on changes to `docs/spec.md`, `docs/threat-model.md`, `docs/residuals.md` and `README.md`, so that a change of the source rebuilds and checks the site. The Help screen of spec 056-chat-screens R18 carries §1's two lists alone; `check_s062_t03_r03_promises` in `scripts/doc_lint.py` MUST fail when the English string resources of Help on any platform differ from §1's two lists, or when the root `README.md`, which keeps its plain-words version, lacks its link to §1 as the normative list or has more bullets in a list than §1.
- R4 Every content entry of `landing/src/content/` other than those of `landing/src/content/beta/` (the tester letter of spec 063-beta, which states no property of the system and is not a public page) MUST carry a `source` field, required by the Zod schema of `landing/src/content.config.ts`, that names a section of `docs/spec.md` (`§N`) or an ADR (`ADR NNNN`); the landing build fails on an entry without one. Every public page MUST follow the wording rules of `landing/CONTENT.md`: "private", never "anonymous"; every promise next to its limit. `check_s062_t04_r04_wording` MUST fail on the words of `landing/src/content/forbidden-words.json`, one list per UI language (English "anonymous", "untraceable", "military-grade", "unbreakable", and each language's equivalents, reviewed by that language's translator), in any page of that language and in the store texts of specs 051-android-mvp and 052-ios-mvp.
- R5 Every translated page, every translated Help string of spec 056-chat-screens R18, and the tester letter of spec 063-beta, MUST record the SHA-256 of the English source it translates and the name of its reviewer, a speaker of that language named in the pull request that adds it. The hash covers the source sections the page is built from, extracted as the build extracts them (for "Promises and limits", §1's two lists and §2's table; for "Known residual risks", `docs/residuals.md`; for another page, its English content entry), not the whole file. A translation whose recorded hash differs from its source's current one is stale. A language whose translation of a page has no reviewer, or is stale, MUST be built as the English page, with a line in that language, itself reviewed, saying the page is not translated yet (O-Q3); the beta does not wait for it. `check_s062_t05_r05_translations` reports every stale or unreviewed translation, and fails only if one of them would be shown instead of the English page.
- R6 Before the beta, `README.md`'s status line MUST give the phase and link the "Known residual risks" page, and `.github/SECURITY.md` MUST link "Promises and limits" and "Known residual risks" and carry the review's result (spec 061-threat-review R8). In the pull request that marks this spec `accepted`, `landing/CONTENT.md`'s route table and its "planned" list MUST name the seven routes of R1, and `landing/README.md`'s tree the new content folders.
- R7 Every in-app text that `docs/spec.md` or a spec fixes word for word as a security warning or instruction, and that specs 053-device-security, 054-qr-invite, 055-verify-ui and 056-chat-screens list as such (the export warning, "scan only with this app", the retire and regenerate explanations, the key-used-elsewhere banner, the verification instructions, the impersonation warnings), and every store text of specs 051-android-mvp R10 and 052-ios-mvp R10, MUST follow the rule of R5 as a translated page does: its translation records the SHA-256 of the English string it translates and its reviewer, and a language whose translation of one of them has no reviewer, or is stale, shows the English text for that string (O-Q3); a store listing in such a language is submitted in English. `check_s062_t07_r07_warning_translations` checks them.
- R8 The site MUST be the static build of `landing/` (Astro) made by `.github/workflows/landing.yml` and served by a static host, with no tracker, no analytics, no cookie and no third-party asset: every script, style sheet, font, image and media file it loads is served from the landing's own host, and no page makes a request to another host when it loads. Every page MUST carry, in its `<head>`, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; form-action 'self'; base-uri 'none'">`, which the browser enforces for every way a page could reach another host (a preconnect or prefetch, an SVG `href`, an `<object>`, a poster, a form, a CSS `image-set()`); links a visitor follows (`<a href>`) are allowed.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Languages | English source and the four translations of §12 | the English page shown for that language |
| A translation | its recorded hash equals its source sections' current one, and it names its reviewer | the English page built and shown, the staleness reported; the lint fails only if a stale translation would be shown |
| Content entries | each with a `source` naming `§N` or `ADR NNNN`, `beta/` excepted | the landing build fails |
| Forbidden words | none in a page or store text of their language | the lint fails |
| A security warning or store text in a language | its recorded hash equals the English string's, and it names its reviewer | the English text shown or submitted |
| Requests a page makes when it loads | to the landing's own host only | the check fails |

## Interface

```
landing/src/content/security/, residuals/, guide/, server/, verify/, privacy/   R1, in five languages
landing/src/content/forbidden-words.json                                      R4
landing/src/content.config.ts                                                 the source field (R4)
.github/workflows/landing.yml                                                 the site's build (R8) and the path triggers (R3)
scripts/doc_lint.py                                                           check_s062_* (R3–R5, R7, R8)
```

**PR slices** (AGENTS 14): (a) the promises and residuals pages built from `docs/`, the path triggers and the Help check (R1, R3); (b) the privacy policy (R2); (c) the guide, server and verify pages (R1); (d) the source field, the wording check and the translation record (R4, R5); (e) the README, SECURITY and landing-plan links (R6); (f) the translations, the in-app warnings' and the store texts' records (R7); (g) the static-site check (R8).

## Security

- A user or an operator can find every accepted limit in one page, in their language (R1), taken at build time from the one list of spec 061-threat-review R2 (R3), so no limit is known only to those who read the specs, and the site cannot fall behind a spec.
- The privacy policy names what the project's own server keeps and for how long from the spec values, what its operator sees live, and what lies outside the app's reach (R2), so a user does not read "nothing is kept" where metadata and addresses are.
- The wording rules, the source field and the forbidden words in every language (R4) keep the public texts from overclaiming, which in a privacy tool is itself a risk: a user who believes they are anonymous takes risks the system does not cover.
- A translation that nobody checked, or that fell behind its English source, is never shown: the English page is (R5), so no language promises more than the reviewed text. The same holds for the in-app security warnings and the store texts (R7), where a wrong translation would mislead a user at the moment of a trust decision.
- The site loads nothing from another host (R8), so reading the security pages or checking a download tells no third party about it; the landing's own host still sees every visitor's address, which the privacy policy says (R2).
- The operator of a self-hosted server sees the address of every member who connects to it, with the time and the channel, which the "Run your own server" page states (§2): a documented residual.
- Deleting a message or leaving a channel removes it from the files the app keeps, but a copy of the device's storage made earlier (a file-system snapshot, a backup outside the app's exclusions, flash wear) may still hold the encrypted files, readable with `K_db` (§2, "Forensic analysis"): a documented residual.
- A member can forward, screenshot and prove the authorship of what others write, since messages are signed, and learns the others' habits and style (§2, "Dishonest member"): a documented residual.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s062_t01_r01_pages`: the landing build produces the seven routes in the five languages; the security page links `/security.atom`, and the "Run your own server" and privacy pages link `docs/public-server.md`, the privacy page also the "Requests from authorities" page; the English "Check a download" page holds the `check-novalidate` command with both namespaces and the hash command of spec 060-reproducible-builds R8, in that order; non-automatable, the human reviewer's reading of the English text is recorded in the pull request.
- T02 (covers R2): `check_s062_t02_r02_privacy`: the English privacy page names each item of R2, the default server, the DNS resolver, the purge interval, snapshots and what the operator sees live, and cites specs 000, 011, 032, 033, 035 and 053 and `docs/spec.md` §2; a duration in the page that differs from the value in its cited spec fails; with 062-R2 open, the check fails once this spec is `implemented`.
- T03 (covers R3): `check_s062_t03_r03_promises`: a word changed in §1 changes the built page with no edit under `landing/`; a Help string that differs from §1 fails; a README without the §1 link, or with an extra bullet, fails; `landing.yml` lists the four path triggers.
- T04 (covers R4): the landing build fails on a content entry without `source`, and passes on an entry of `beta/` without one; `check_s062_t04_r04_wording`: a Spanish page with "anónimo" fails, an English one with "anonymous" fails, and a store text with "untraceable" fails.
- T05 (covers R5): `check_s062_t05_r05_translations`: a residual added to `docs/residuals.md` makes the four translations of "Known residual risks" stale, the check reports them and passes, and the build shows the English page with the "not translated yet" line in each language; a build that would show a stale translation fails; a change elsewhere in `docs/spec.md` stales nothing; a Catalan Help string whose hash differs from §1's lists is reported; a page with no reviewer is built as the English page.
- T06 (covers R6): `check_s062_t06_r06_links`: the README and `.github/SECURITY.md` hold the links of R6; once this spec is `accepted`, `landing/CONTENT.md` names the seven routes.
- T07 (covers R7): `check_s062_t07_r07_warning_translations`: a Catalan translation of the key-used-elsewhere banner whose hash differs from the English string's makes the Catalan build show the English banner and is reported; a string that specs 053–056 list as a security warning with no reviewer shows in English; a store text without a reviewer in a language is flagged for English submission; a non-listed string is not checked.
- T08 (covers R8): `check_s062_t08_r08_static_site`: every built page carries the policy of R8 exactly; each built page, loaded in a headless browser with the site served locally, makes no request to another host, and a fixture page loading a font from another host, a `<script src>` to another host, a CSS `url()` to another host or a `<link rel="preconnect">` to another host fails; an `<a href>` to GitHub passes; the privacy page names the landing host's access logs; the "Run your own server" page says that no image is published to a registry and that the apps carry no list of servers.

## Vectors

None.

## Acceptance criterion

The documentation lint and the landing build green. Non-automatable: the human reviewer reads every English page; each translation shown is read by its named reviewer.

## Out of scope

- The landing's design and components (`landing/CONTENT.md` and its own work).
- Marketing. The store screenshots and graphics are specs 051-android-mvp R10's and 052-ios-mvp R10's.
- The developer documentation (`AGENTS.md`, `.github/CONTRIBUTING.md`, the specs), which already exists.
- `docs/residuals.md` itself and its check, which are spec 061-threat-review R2's.

## Open questions

- [ ] 062-R2: the data controller of the project's public server, its contact address and its jurisdiction, for the privacy policy; the human owner's decision, together with the server of 063-R1 and the host and jurisdiction of 066-R1.

## History

- 2026-09-27 draft
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): the privacy policy made exact from the spec values, with metadata, the 60 s of addresses, what lies outside the app and the controller; every page built from `docs/`, with path triggers; Help checked against §1 alone; a `source` field per entry; forbidden words per language; translations tied to their English source's hash, and an unreviewed or stale one shown in English (O-Q3); the residuals page renamed "Known residual risks" and its list owned by spec 061; the landing plan amended at acceptance
- 2026-09-27 revised after audit O round 2 (`docs/audit-log.md`): a stale translation built as English and only reported, the hash over the extracted source sections, Help's translations and the "not translated yet" line reviewed; the privacy policy names the default server, the DNS resolver, the purge interval, snapshots and what the operator sees live; the verify page's steps in order with the out-of-band check first, Rekor, retired keys and the rotation statement; residual citations to 060 R4 and 064 R4; the tester letter exempt from the `source` field; O-Q3 cited from "Audit O"
- 2026-09-27 revised after audit O round 3 (`docs/audit-log.md`): the verify page's first step is `ssh-keygen -Y check-novalidate` with the tag's namespace and a printed fingerprint compared out of band, followed by the exact hash command; the operator's live view cited from §2's first row
- 2026-09-28 revised after audit P (`docs/audit-log.md`): R7 the reviewer-and-hash rule over the in-app security warnings of 053–056 and the store texts; R8 the landing as a static site with no third-party asset; the privacy policy names the landing host's access logs; "Run your own server" says no image is published to a registry and that no server list is in the apps (§12); three §2 residuals worded as documented residuals; store screenshots moved to 051 and 052
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): a seventh route, "Requests from authorities" (spec 066 R8), and links to `docs/public-server.md` and the security feed (R1, R2); a Content-Security-Policy on every page and a headless-browser check (R8); 062-R2 coupled with 066-R1; Blocks names 066
- 2026-09-28 accepted (Marc Vilardebó)
