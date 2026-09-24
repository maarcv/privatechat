# SEO checklist

Every page on the landing must pass this list. SEO baseline isn't optional for a company site.

## The head — full template

This is the `<head>` for `BaseLayout.astro`. Per-page overrides come via props.

```astro
---
// src/layouts/BaseLayout.astro
import { getEntry } from 'astro:content';
import '../styles/global.css';

interface Props {
  title?: string;
  description?: string;
  image?: string;            // absolute or root-relative path to OG image
  noindex?: boolean;
}

const settings = await getEntry('site', 'settings');
if (!settings) throw new Error('Site settings missing at src/content/site/settings.json');

const {
  title: pageTitle,
  description: pageDescription,
  image,
  noindex = false,
} = Astro.props;

const title = pageTitle
  ? `${pageTitle} — ${settings.data.name}`
  : `${settings.data.name} — ${settings.data.tagline}`;

const description = pageDescription ?? settings.data.description;
const canonical = new URL(Astro.url.pathname, Astro.site ?? settings.data.url).href;
const ogImage = new URL(image ?? '/og-default.png', Astro.site ?? settings.data.url).href;
---
<!doctype html>
<html lang={settings.data.locale}>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="generator" content={Astro.generator} />

    <title>{title}</title>
    <meta name="description" content={description} />
    <link rel="canonical" href={canonical} />

    {noindex && <meta name="robots" content="noindex, nofollow" />}

    {/* Open Graph */}
    <meta property="og:type" content="website" />
    <meta property="og:title" content={title} />
    <meta property="og:description" content={description} />
    <meta property="og:url" content={canonical} />
    <meta property="og:image" content={ogImage} />
    <meta property="og:site_name" content={settings.data.name} />
    <meta property="og:locale" content={settings.data.locale} />

    {/* Twitter */}
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content={title} />
    <meta name="twitter:description" content={description} />
    <meta name="twitter:image" content={ogImage} />

    {/* Icons */}
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />

    {/* Sitemap */}
    <link rel="sitemap" href="/sitemap-index.xml" />
  </head>
  <body class="bg-white text-gray-900 antialiased font-sans">
    <slot />
  </body>
</html>
```

## `astro.config.mjs` requirements

The `site` field is **required** for sitemap generation and canonical URLs. Without it, `Astro.site` is `undefined` and the template above falls back to settings.

```js
export default defineConfig({
  site: 'https://example.com',  // user replaces with real domain
  integrations: [sitemap()],
  vite: { plugins: [tailwindcss()] },
});
```

## `public/robots.txt`

Static is fine for a single-domain landing:

```
User-agent: *
Allow: /

Sitemap: https://example.com/sitemap-index.xml
```

Or generate it dynamically so the sitemap URL stays in sync with `site`:

```ts
// src/pages/robots.txt.ts
import type { APIRoute } from 'astro';

export const GET: APIRoute = ({ site }) => {
  if (!site) throw new Error('site is not set in astro.config.mjs');
  const body = `User-agent: *
Allow: /

Sitemap: ${new URL('sitemap-index.xml', site).href}
`;
  return new Response(body, { headers: { 'Content-Type': 'text/plain' } });
};
```

The dynamic version is the senior choice — one source of truth.

## OG image strategy

Three options, pick based on user need:

1. **Single static image** (`public/og-default.png`, 1200×630). Fast, simple, fine for most single-page landings. **Default to this.**
2. **Per-page static images** referenced via the `image` prop on `BaseLayout`. Use when different sections of the site deserve different previews.
3. **Generated at build time with `@vercel/og` or similar**. Overkill for a static landing; only do this if the user explicitly asks.

The image needs to be at least 1200×630 (preferred). Recommend the user supply one; provide a placeholder SVG/PNG if they don't have one yet.

## Structured data (JSON-LD)

For a company landing, the minimum is an `Organization` schema in the head:

```astro
<script type="application/ld+json" set:html={JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: settings.data.name,
  url: settings.data.url,
  logo: new URL('/logo.png', settings.data.url).href,
  description: settings.data.description,
  ...(settings.data.contact.email && { email: settings.data.contact.email }),
  ...(settings.data.contact.phone && { telephone: settings.data.contact.phone }),
  ...(settings.data.social && {
    sameAs: Object.values(settings.data.social).filter(Boolean),
  }),
})} />
```

Add this only if the user wants it. It's a nice-to-have, not part of the strict baseline.

## Lighthouse / perf checklist

Before declaring done, the landing should comfortably score 95+ in Lighthouse:

- **Images:** `<Image />` for everything in `src/assets/`, never raw `<img>` tags for local assets. Above-the-fold images get `loading="eager"` and `fetchpriority="high"`.
- **Fonts:** self-hosted if possible, `font-display: swap`, preload the variable woff2 if it's blocking render.
- **JS:** zero by default. Each `client:*` directive is a deliberate cost. `client:visible` or `client:idle` beats `client:load`.
- **CSS:** Tailwind v4 tree-shakes automatically. Don't ship a CSS framework on top of it.
- **Headings:** one `<h1>` per page (in the Hero). Sections use `<h2>`. Nested content uses `<h3>+`. Skipping levels is an a11y fail.
- **Color contrast:** AA minimum (4.5:1 for body text). Check the accent color against the backgrounds it's used on.
- **Alt text:** required on every image. `alt=""` is valid for decorative images, but be intentional — most images aren't decorative.

## Per-page overrides

Pages can override head fields by passing props to the layout:

```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
---
<BaseLayout
  title="Pricing"
  description="Simple, transparent pricing for teams of every size."
  image="/og-pricing.png"
>
  <Pricing />
</BaseLayout>
```

The title becomes `"Pricing — Company Name"` thanks to the template logic in `BaseLayout`.

## What gets queried from MCP

If the user asks for any of these, query `Astro:search_astro_docs` first — defaults shift between versions:

- View Transitions API (Astro's `<ClientRouter />`)
- i18n routing
- SSR / on-demand rendering (changes how canonical/sitemap behave)
- Adapter-specific deploy details
