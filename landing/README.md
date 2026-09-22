# Landing

Static, multilingual public site of the project, built with Astro and Tailwind. It explains what
the chat promises and does not promise (`docs/spec.md` §1) and links to the clients and the source.

## What it is not

- Not a client. It never holds a key, a channel or a message, and it ships no code that touches the
  protocol (ADR 0017: there is no hosted web client in v1). If a page ever needs to talk to a
  server, that is a new decision, not a feature of this directory.
- Not part of the Cargo workspace. Nothing here is compiled with the crates, linted by
  `cargo clippy` or checked by `cargo deny`. Its dependencies are managed by `package.json` and
  its lockfile, kept to the minimum and watched by dependabot.

## Languages

English is the source and default language. The site is published in the same five languages as
the clients (`docs/spec.md` §9): English, Spanish, French, Catalan and Italian, one route prefix per
language. The copy lives in Astro content collections, one folder per language, never inline in a
component. This directory is the explicit exception to AGENTS.md rule 11: the user-facing copy is
translated; code, comments, file names and commit messages stay in English.

## Layout and conventions

The site follows the `astro-landing` skill in `.claude/skills/astro-landing/` (scoped to this
directory): `.astro` components by default, React only for real client-side interaction, Tailwind for
styling, TypeScript with typed props, content in collections with a Zod schema. Read the skill
before writing here.

```
src/
├─ content/{site,home,security}/<lang>.json   ← all the copy, one file per language
├─ content.config.ts                          ← the Zod schema of that copy
├─ lib/                                       ← what is not copy: languages, addresses,
│                                                section anchors, the readers of docs/
├─ components/{ui,nav,sections,security,illustrations}/
├─ layouts/BaseLayout.astro
└─ pages/{index.astro,[lang]/{index,security}.astro}
```

The site ships no JavaScript: there is no island, the menu is a `<details>` element and light
and dark come from `prefers-color-scheme`. Nothing is fetched from a third party — no font, no
script, no analytics — which is the position of `docs/spec.md` §8 "Telemetry" applied to the
website. What the page says therefore does not depend on anything the reader's browser goes and
downloads from somewhere else.

Addresses are not copy: they live in `src/lib/links.ts` and the content refers to them by name,
so a URL is written once instead of once per language.

## What the site copies from the repository

The security page reproduces `docs/spec.md` §1 and `docs/threat-model.md` word for word, and
`CONTENT.md` requires it not to drift from them. It therefore does not hold a copy: `src/lib/docs.ts`
reads those files at build time, and so does the project status shown in the header, which comes
from the root `README.md`. If a list, a table or a heading moves, the build fails with a message
naming what it could not find, instead of the site quietly going stale.

`src/lib/limits.ts` says which accepted limitation belongs to which group on that page. That is
structure, not copy, so it is not translated; the build checks that every sentence of the document
lands in exactly one group.

## Build and deploy

```
npm install
npm run dev      # local preview
npm run check    # types, must be clean
npm run build    # static output in dist/
```

The output is static files, deployed to a static host independently of `deploy/`, which is the
reference deployment of the exchange server. `.github/workflows/landing.yml` runs these checks only
when `landing/` changes. The Rust jobs of `.github/workflows/ci.yml` still run on a pull request
that touches only this directory: narrowing their triggers would change spec 001-ci, so it is left
to that spec.

## Status

The site is built and its English text is complete: the home page with the six sections of
`CONTENT.md` and the `/en/security/` page with the promises, the limits and the adversary table.
`npm run check` and `npm run build` are clean.

Pending, and each one is a decision for the reviewer rather than work that is merely unfinished:

- **The other four languages.** The routes, the language picker and the schema are in place; a
  language appears as soon as its files exist under `src/content`. Only `en` exists, because the
  translations are made from the accepted English text. The security page quotes the English
  documents; translating it needs a field in the schema for the translated sentences, which is not
  written yet so as not to guess its shape.
- **The domain.** There is none, so `site` in `astro.config.ts` is `https://privatechat.invalid`
  (RFC 2606), the same convention `DEFAULT_SERVER_URL` follows. The canonical URLs and
  `robots.txt` carry it and have to be changed when a real domain is decided.
- **The social preview image.** There is no visual identity beyond the favicon, so the pages carry
  Open Graph title, description and URL, but no `og:image`.
- The open questions of `CONTENT.md` that this work answered are the product name (`privatechat`),
  the visual identity (the proposal in that file) and no analytics; the rest are still open there.
