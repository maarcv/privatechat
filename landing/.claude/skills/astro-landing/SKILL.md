---
name: astro-landing
description: Build a production-quality static landing page for a company using Astro + Tailwind CSS. Use this skill whenever the user asks for a landing page, marketing site, company website, "una web per la meva empresa", a one-pager, hero-with-features site, or any static promotional site — even if they don't explicitly name Astro. The skill enforces senior-level code (well-structured, reusable components, type-safe), uses Astro-native components as the default and React only where genuine client-side interactivity is needed, styles everything with Tailwind, and stores variable content (copy, features, testimonials) in Astro Content Collections so the site stays editable without touching components. Consults the Astro MCP (`Astro:search_astro_docs`) for any API detail the skill doesn't pin down.
---

# Astro Landing Page

Build a static landing page for a company with Astro + Tailwind. Code must look like a senior wrote it, not a junior.

## Non-negotiable rules

1. **Astro components (`.astro`) are the default.** Only reach for React when there's real client-side state or behavior the user will interact with (mobile menu toggle, accordion, carousel, form with validation). Static UI — hero, features grid, pricing cards, footer — is always `.astro`.
2. **Tailwind for all styling.** No inline `style=""`, no `<style>` blocks except when truly necessary (e.g. third-party widget overrides). Tailwind v4 via the Vite plugin — never the legacy `@astrojs/tailwind` integration.
3. **Content in Content Collections, not hardcoded.** Hero copy, features list, testimonials, FAQ, pricing tiers — all of these live in `src/content/` as JSON or Markdown with a Zod schema. Components receive content via props or query the collection. The client must be able to edit a JSON file to change the site without touching `.tsx` or `.astro`.
4. **TypeScript everywhere.** Every component declares `interface Props`. No `any`. No `Astro.props` destructured without a type.
5. **One responsibility per component.** A `Hero.astro` renders a hero. A `Section.astro` is a layout primitive. Don't put three sections in one file because they "go together on the page".
6. **Consult the Astro MCP whenever uncertain.** Before guessing at a config flag, integration name, directive, or API surface — call `Astro:search_astro_docs` with a relevant query. The docs evolve; assumptions rot. This is required, not optional.

## Workflow

Follow these steps in order. Don't skip ahead.

### 1. Gather requirements

If the user gave a vague prompt ("make me a landing for my company"), ask for the minimum you need before writing code. Don't ask everything at once — keep it tight. The essentials are:

- Company name and one-line description
- Sections they want (hero, features, pricing, testimonials, FAQ, CTA, contact — typical set, confirm)
- Visual tone (corporate / playful / minimal / bold) and primary accent color if they have a preference
- Deployment target if known (static host like Netlify/Vercel/Cloudflare — affects nothing for static output but worth knowing)

If the user just says "make something nice", make reasonable senior choices and tell them you did. Don't paralyze on questions.

### 2. Scaffold the project

Use `npm create astro@latest` with the minimal template, then add integrations. Don't use the "blog" or "starter" templates — they bring noise this skill doesn't need.

```bash
npm create astro@latest <project-name> -- --template minimal --typescript strict --no-git --install
cd <project-name>
npx astro add tailwind --yes
npx astro add react --yes        # only if real interactivity is needed; skip otherwise
npx astro add sitemap --yes      # SEO baseline
```

After scaffolding:
- Confirm `astro.config.mjs` has `site: 'https://example.com'` set (sitemap needs it; the user can replace later).
- Confirm `src/styles/global.css` exists with `@import "tailwindcss";` and is imported from the base layout.
- Delete the placeholder `index.astro` content — you'll rewrite it.

If you're unsure about any current CLI flag, integration name, or config option, call `Astro:search_astro_docs` before running the command. Example queries: `"astro add tailwind cli flags"`, `"astro create minimal template typescript"`, `"sitemap configuration site option"`.

### 3. Plan the structure before writing any code

Lay out the directory tree on paper (or in a comment) before creating files. Senior code is structured; junior code accretes.

```
src/
├── components/
│   ├── ui/              # Generic, reusable primitives: Button, Container, Section, Badge
│   ├── sections/        # Page sections: Hero, Features, Pricing, Testimonials, FAQ, CTA, Footer
│   └── islands/         # React components that hydrate (only if needed)
├── content/
│   ├── config.ts        # Collection schemas (Zod)
│   ├── site/            # Single-entry collection: site-wide settings (name, nav, footer)
│   ├── features/        # One entry per feature
│   ├── testimonials/    # One entry per testimonial
│   └── pricing/         # One entry per pricing tier
├── layouts/
│   └── BaseLayout.astro # <html>, <head>, SEO meta, slot
├── pages/
│   └── index.astro      # Composes sections; near-zero logic
├── styles/
│   └── global.css       # Tailwind import + design tokens via @theme
└── assets/              # Images that Astro should optimize (NOT public/)
```

`src/components/ui/` is the design-system layer. `src/components/sections/` is the page-composition layer. Sections consume `ui/` primitives. Pages consume sections. Don't let a section reach into a page's logic.

### 4. Build in this order

Building bottom-up means each layer is testable in isolation and the page composition at the end is trivial.

1. **Design tokens** — Define colors, fonts, spacing in `src/styles/global.css` using Tailwind v4's `@theme` directive. The accent color the user picked goes here, not scattered as `bg-blue-600` across thirty files.
2. **Content schemas** — Write `src/content/config.ts` with one `defineCollection` per content type, each with a Zod schema. Strict types. Required fields are required.
3. **Seed content** — Create the JSON/Markdown entries with placeholder-but-realistic content for the company. No "Lorem ipsum"; use plausible copy that fits the company.
4. **UI primitives** — `Button.astro`, `Container.astro` (max-width wrapper), `Section.astro` (vertical padding + container). Each with typed props and Tailwind classes. Use `class:list` or string concatenation for variant classes, not runtime CSS-in-JS.
5. **Layout** — `BaseLayout.astro` with `<html lang>`, full `<head>` (charset, viewport, title, description, canonical, OG tags, sitemap link, favicon, Tailwind import), and a single `<slot />`.
6. **Sections** — One file each. Each section reads its content from the collection via `getCollection` / `getEntry`, not from props passed down from the page. Exception: section-specific props like `id` for anchor navigation.
7. **Islands (only if needed)** — Mobile menu toggle, form, etc. in `src/components/islands/` as `.tsx`. Hydrate with the lightest directive that works: `client:visible` > `client:idle` > `client:load`. Never default to `client:load`.
8. **Compose the page** — `src/pages/index.astro` is short: layout + sections in order. No business logic.

### 5. SEO baseline (always)

Every landing needs this — it's non-negotiable for a company site:

- `<title>` and `<meta name="description">` from site collection, overridable per-page via layout props
- Open Graph (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`) and Twitter card meta
- `<link rel="canonical">` built from `Astro.url` and `Astro.site`
- `<link rel="sitemap" href="/sitemap-index.xml">` (sitemap integration generates the XML)
- `lang` attribute on `<html>` set correctly
- `public/robots.txt` with sitemap reference
- Favicon (provide a placeholder SVG if the user has no asset)

If the user asks for more (analytics, JSON-LD structured data, hreflang for i18n), consult `Astro:search_astro_docs` for the current recommended approach.

### 6. Images

- Use `<Image />` from `astro:assets` for any image in `src/assets/`. Always provide `alt`. Astro handles `width`, `height`, format conversion, and lazy loading.
- For above-the-fold hero images, pass `loading="eager"` and `fetchpriority="high"`.
- Reserve `public/` for files that must be served as-is (favicon, `robots.txt`, downloadable PDFs). Don't put hero images there — they won't be optimized.

### 7. Verify before declaring done

Run these and fix anything that fails — don't hand back a broken project:

```bash
npm run build        # must succeed with zero errors
npx astro check      # type-check, must pass
```

If `astro check` complains about types in `getCollection` results, the schema is wrong or out of sync — fix the schema, don't `as any` the result.

## Senior vs junior code — the actual difference

These are the patterns reviewers will look for. The skill is judged on whether the output exhibits them.

### Props are typed and have sensible defaults

```astro
---
// Good
interface Props {
  variant?: 'primary' | 'secondary' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  href?: string;
  class?: string;
}
const { variant = 'primary', size = 'md', href, class: className } = Astro.props;
---
```

```astro
---
// Junior — typeless, no defaults, magic strings everywhere downstream
const { variant, size, href } = Astro.props;
---
```

### Variant classes via a lookup, not chained ternaries

```astro
---
const variants = {
  primary: 'bg-accent text-white hover:bg-accent/90',
  secondary: 'bg-gray-100 text-gray-900 hover:bg-gray-200',
  ghost: 'bg-transparent text-accent hover:bg-accent/10',
} as const;

const sizes = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-base',
  lg: 'px-6 py-3 text-lg',
} as const;
---
<a class:list={['rounded-lg font-medium transition', variants[variant], sizes[size], className]} href={href}>
  <slot />
</a>
```

### Sections own their content query

A section component knows where its data lives. Pages don't shuttle data around.

```astro
---
// src/components/sections/Features.astro
import { getCollection } from 'astro:content';
import Section from '../ui/Section.astro';
const features = await getCollection('features');
features.sort((a, b) => a.data.order - b.data.order);
---
<Section id="features" class="bg-gray-50">
  <h2 class="text-3xl font-bold text-center mb-12">What we do</h2>
  <div class="grid md:grid-cols-3 gap-8">
    {features.map(({ data }) => (
      <article class="...">
        <h3>{data.title}</h3>
        <p>{data.description}</p>
      </article>
    ))}
  </div>
</Section>
```

### Pages are compositions, not implementations

```astro
---
// src/pages/index.astro
import BaseLayout from '../layouts/BaseLayout.astro';
import Hero from '../components/sections/Hero.astro';
import Features from '../components/sections/Features.astro';
import Testimonials from '../components/sections/Testimonials.astro';
import Pricing from '../components/sections/Pricing.astro';
import FAQ from '../components/sections/FAQ.astro';
import CTA from '../components/sections/CTA.astro';
---
<BaseLayout>
  <Hero />
  <Features />
  <Testimonials />
  <Pricing />
  <FAQ />
  <CTA />
</BaseLayout>
```

That's the whole page. If `index.astro` ends up with logic, the logic belongs in a section or a util.

### React only when it earns its place

Junior: ships a React Hero with `client:load` because that's what they know.
Senior: ships an `.astro` Hero with zero JS, and a 30-line `MobileMenu.tsx` with `client:idle` because that's the only thing that needs state.

A React island is justified when:
- It needs `useState` / event handlers tied to component state
- It interacts with browser APIs that need a hydration boundary
- It's a third-party React-only component the user requires

It's not justified for:
- Static cards with hover effects (Tailwind handles that)
- A list rendered from data (Astro handles that better, with no JS shipped)
- "It might be interactive later" (add it later, when it actually is)

## When to consult the Astro MCP

Use `Astro:search_astro_docs` proactively, not as a last resort. Cheap to call, expensive to be wrong about. Specifically:

- Before adding any integration: query its current install command and config shape
- Before using a directive you haven't used in months (`client:*`, `set:html`, `is:inline`): verify behavior
- Before configuring `image`, `i18n`, `vite`, or `experimental` flags: confirm current option names
- If a build error mentions something Astro-specific: search the error message before guessing

Pattern: search → read the snippet → write the code. Don't paraphrase docs from memory when one tool call settles it.

## Reference files

For deeper detail on specific topics, the skill bundles these references. Read them as needed:

- `references/tailwind-setup.md` — Tailwind v4 setup, design tokens with `@theme`, dark mode, typography plugin
- `references/content-collections.md` — Recommended schemas for a landing's collections (site, features, testimonials, pricing, faq)
- `references/seo-checklist.md` — Full SEO head template, OG image strategy, structured data examples
- `references/component-patterns.md` — Copy-paste-quality patterns for Button, Container, Section, Card, plus a senior-grade MobileMenu island

Don't read all four upfront. Read the one that matches the step you're on.

## Anti-patterns to avoid

- Importing React for static rendering ("but I'm more comfortable in JSX") — write `.astro`.
- One `index.astro` of 400 lines containing every section inline — split.
- `bg-[#3b82f6]` arbitrary values for the brand color used in 20 places — define a token.
- Markdown frontmatter without a Zod schema — you lose type safety and silent typos break the build later.
- `client:load` on every island — measure, then pick the lightest directive that works.
- Putting hero images in `public/` — they won't be optimized.
- No `alt` on images — accessibility failure, also breaks Lighthouse.
- Skipping `npm run build` before handing off — runtime errors that the dev server hid will bite the user.
