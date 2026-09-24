# Landing — content plan

What the public site says, section by section, before any component is written. Every claim
about privacy points to its source in `docs/spec.md` (§) or an ADR; a sentence with no source
does not go on the site. English is the source text; the other four languages are translations
of the accepted English (`docs/spec.md` §9).

Wording rules for the whole site:

- "Private", never "anonymous": without Tor the server sees an IP, and an IP is a person (§1).
- "Cannot read", never "cannot see": the server sees that a channel exists and when it is read (§2).
- Every promise sits next to its limit. The site never lists guarantees without the page that
  lists what is not guaranteed.
- No downloads, no store badges and no server address until they exist (§10: phase 0 today).
  A status line says which phase the project is in and links to the repository.

## Site structure

One long page per language with six sections, plus one separate page per language for the
full "promises and limits" table, because it is long and it must be quotable on its own.

| Route | Page | Sections |
| --- | --- | --- |
| `/{lang}/` | Home | 1 Idea · 2 What it is · 3 How it works · 4 Run it yourself · 5 Check it yourself · 6 Open source |
| `/{lang}/security/` | Promises and limits | The three lists of section 7 and the adversary table |

Languages and prefixes: `en` (source, default), `es`, `fr`, `ca`, `it`. Navigation: the six
section anchors, the security page, the repository. Footer: licence, repository, security page.

## 1. Idea — a free and private internet for everyone

Purpose: say why the project exists before saying what it does. This is the only section
whose text is not derived from the spec; it is the project's own voice and needs the
reviewer's approval as such.

Key messages:

- Privacy is a default, not a feature for experts. Talking with the people you choose, without
  anyone in between able to read it, should be as ordinary as talking in a room.
- The tools for that have to be simple, open and verifiable by anyone, not trusted on the
  word of whoever runs them.
- Every piece that does not bring a demonstrable guarantee is a place to fail, so it is left
  out (§1, "uncompromising and simple").

Call to action: scroll to what it is; link to the repository.

## 2. What it is — a private group chat

Source: §1 first paragraph, README.

Key messages:

- End-to-end encrypted group chat where the server is only a mailbox: no accounts, no
  identities, nothing it can read (§1).
- You join a channel by receiving its config in person (a QR code) or as a password-protected
  file; there is no sign-up (§1, §5).
- Desktop, Android and iOS, over one cryptographic core in Rust (§1, ADR 0012).
- Open source; anyone can run the server; every channel lives on the server chosen by whoever
  created it (§1, ADR 0022).
- Messages expire: each channel has a retention time, enforced on the server and on the device
  (§1, ADR 0009, 0014).

What it is not, in one line each, so the visitor does not leave with the wrong idea (§1 "Out
of scope"): no calls, no attachments, no one-to-one with prekeys, no web version (ADR 0017),
no push notifications, no member removal (a new channel is created instead, ADR 0008).

## 3. How it works

Source: §4, §5, §6, §7. Written for a reader who is not a cryptographer; the exact
construction is linked, not repeated.

Four steps, one illustration each:

1. **A channel is a key.** Whoever creates the channel gets a random root key. Everything else
   (the channel's identifier on the server, the message keys, the header key) is derived from
   it. Whoever has the key is in the channel (§4 "Keys", ADR 0001).
2. **The invitation travels outside the system.** QR shown on screen and scanned in person, or
   a `.chatcfg` file protected by seven random words spoken over another channel. The server
   never sees the invitation (§5).
3. **Every message is sealed and signed.** Encrypted with a per-message key, then signed with
   the sender's key for that channel. The server stores an opaque blob padded to a fixed size
   class and does not know who wrote it (§4 envelope, ADR 0013, 0015, 0018).
4. **You verify people, not accounts.** A member is a key that has written. To know it is your
   friend you compare a QR or twelve words in person. Nothing goes through the server (§7, §4
   "User fingerprint", ADR 0005, 0006).

Also in this section, short: one key per device (ADR 0019); no forward secrecy in v1, said
plainly and linked to section 7 (ADR 0004, 0013).

## 4. Run it yourself

Source: §1, §2 rows "Member who operates the self-hosted server" and "Seized or coerced
operator", `deploy/README.md`, ADR 0022, §8 "App settings".

Key messages:

- The server is one binary and one SQLite table, with no secrets and no user accounts. Anyone
  can run one (`deploy/README.md`).
- Each channel picks its server when it is created; the app ships with the project's server as
  the default and it can be changed in the settings or per channel (§1, §8, ADR 0022).
- Running a server means seeing the metadata of the "honest-but-curious server" row and
  nothing else: which channels are read, from which IP, when (§2). Say it, do not hide it.
- Tor and `.onion` are supported for people for whom the IP matters (§2).

Call to action: link to `deploy/README.md`. No copy-paste command on the site until phase 3
ships it; until then the link says "reference deployment, in progress".

## 5. Check it yourself

Source: §2 "Malicious server" mitigations, §8 "Code integrity", §9, §10 phase 6, AGENTS.md,
`specs/`, ADR 0012, 0015, 0017.

Purpose: the site does not ask to be trusted; it says where to look. Five checks, each with a
link:

1. **Read the specification.** Everything the software does is written before it is coded:
   `docs/spec.md`, the ADRs and one spec per feature with numbered requirements and a test for
   each (AGENTS 6, `specs/`).
2. **Read the threat model.** Who can see what, and what we do about it, in one table
   (`docs/threat-model.md`). The same table is section 7 of this site.
3. **Run the test vectors.** The protocol produces fixed bytes for fixed inputs; the vectors
   are published and any independent implementation can check them (spec 015, ADR 0015).
4. **Rebuild the app and compare the hash.** Reproducible builds with published hashes
   (§8 "Code integrity", phase 6). Marked "planned" until phase 6 ships.
5. **No code from the server.** The client never runs code the server sends; there is no web
   client (ADR 0017). Only libsodium, no primitive of our own (§4, AGENTS 2).

## 6. Open source, MIT

Source: `LICENSE`, README, `.github/CONTRIBUTING.md`, AGENTS.md.

Key messages:

- MIT licence: use it, fork it, ship it under your own name, with or without our server.
- How the project works: spec first, human review, tests that cite the requirement, small
  PRs. Link to `CONTRIBUTING.md` and `AGENTS.md`.
- Where help is welcome: independent review of the cryptographic model (phase 6),
  translations of the clients and this site, self-hosting reports, client work once phases 1
  and 2 close (§10).
- Security contact: link to `.github/SECURITY.md`.

## 7. Promises and limits (the `/security/` page)

Source: §1 (two lists, reproduced literally), §2 (table and "Outside the model", reproduced
literally from `docs/threat-model.md`). This page is copied from the docs, not rewritten:
the doc lint keeps the threat table single-sourced and the site must not drift from it.

Structure of the page:

1. **What it promises** — the five items of §1, verbatim.
2. **What it does not promise** — the nine items of §1 plus the three extra items of
   `docs/threat-model.md` "Accepted limitations", verbatim. Group them for reading, keeping
   every sentence:
   - Your device and the people in the channel: compromised device, member who forwards,
     not deniable, local data lost on reinstall or backup restore, desktop processes can
     read the files.
   - The channel key: whoever has it reads everything, past and future, until a new channel;
     no forward secrecy or post-compromise security in v1; a leak from a device leaks the new
     channel too; a full channel is only fixed by a new channel.
   - The server and the network: it can delete or delay; it knows IP and time of every
     listener; the default server is the project's; no push notifications in v1.
   - The operating system and the store: they know the app is installed and when it is used.
3. **Who can see what** — the adversary table of §2, three columns as in the source.
4. **Outside the model** — the one line of §2.
5. **Where this comes from** — links to `docs/spec.md` §1–§2, `docs/threat-model.md`,
   `docs/audit-log.md`, with the version and date of the spec the page was copied from.

Translation note: this page is translated with the same care as the rest, but the English
version is the one that is compared against the docs; the other languages link to it.

## Open questions for the reviewer

- [ ] Product name on the site: "privatechat" as in the repository, or another public name?
- [ ] Domain and the default server address: none yet (`server.invalid`, spec 000 R4). The site
      shows no address until there is one.
- [ ] Section 1 voice: approve or rewrite the three key messages; they are not in the spec.
- [ ] Visual identity: none exists. Proposal: minimal, high contrast, no photographs, one
      illustration per step in section 3, light and dark.
- [ ] Analytics: none, consistent with §8 "Telemetry". Confirm the site also carries no
      third-party scripts or fonts fetched from third parties.
