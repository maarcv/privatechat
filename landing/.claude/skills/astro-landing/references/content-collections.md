# Content Collections for a landing page

The whole point: a non-developer can edit a JSON or Markdown file and the site updates. Components never embed copy directly.

## Where things live

```
src/content/
├── config.ts          # Schemas (Zod). The single source of truth.
├── site/
│   └── settings.json  # Site-wide: name, tagline, nav, footer, social, contact email
├── features/
│   ├── speed.json
│   ├── security.json
│   └── support.json
├── testimonials/
│   ├── alice.json
│   └── bob.json
├── pricing/
│   ├── starter.json
│   ├── pro.json
│   └── enterprise.json
└── faq/
    ├── 01-pricing.md
    └── 02-onboarding.md
```

**Convention:** filename order (`01-`, `02-`) is for humans. Use an explicit `order: number` field in the schema for ordering at render time — never sort by filename.

## `src/content/config.ts` — full template

This file is the contract. Strict Zod schemas catch typos at build time.

```ts
import { defineCollection, z } from 'astro:content';
import { glob, file } from 'astro/loaders';

// ─── Site-wide settings (single entry) ──────────────────────────────────────
const site = defineCollection({
  loader: glob({ pattern: 'settings.json', base: './src/content/site' }),
  schema: z.object({
    name: z.string(),
    tagline: z.string(),
    description: z.string().max(160),  // meta description budget
    url: z.string().url(),
    locale: z.string().default('en'),
    nav: z.array(z.object({
      label: z.string(),
      href: z.string(),
    })),
    cta: z.object({
      label: z.string(),
      href: z.string(),
    }),
    social: z.object({
      twitter: z.string().url().optional(),
      linkedin: z.string().url().optional(),
      github: z.string().url().optional(),
    }).optional(),
    contact: z.object({
      email: z.string().email(),
      phone: z.string().optional(),
      address: z.string().optional(),
    }),
  }),
});

// ─── Features ───────────────────────────────────────────────────────────────
const features = defineCollection({
  loader: glob({ pattern: '*.json', base: './src/content/features' }),
  schema: ({ image }) => z.object({
    title: z.string(),
    description: z.string(),
    icon: z.string(),               // lucide icon name, e.g. 'zap'
    order: z.number().int().min(0),
  }),
});

// ─── Testimonials ───────────────────────────────────────────────────────────
const testimonials = defineCollection({
  loader: glob({ pattern: '*.json', base: './src/content/testimonials' }),
  schema: ({ image }) => z.object({
    quote: z.string(),
    author: z.object({
      name: z.string(),
      title: z.string(),
      company: z.string(),
      avatar: image().optional(),   // image() returns ImageMetadata for <Image />
    }),
    order: z.number().int().min(0),
  }),
});

// ─── Pricing tiers ──────────────────────────────────────────────────────────
const pricing = defineCollection({
  loader: glob({ pattern: '*.json', base: './src/content/pricing' }),
  schema: z.object({
    name: z.string(),
    price: z.object({
      monthly: z.number(),
      yearly: z.number(),
      currency: z.string().length(3).default('EUR'),
    }),
    description: z.string(),
    features: z.array(z.string()).min(1),
    cta: z.object({
      label: z.string(),
      href: z.string(),
    }),
    highlighted: z.boolean().default(false),
    order: z.number().int().min(0),
  }),
});

// ─── FAQ (Markdown — answers may want formatting) ───────────────────────────
const faq = defineCollection({
  loader: glob({ pattern: '*.md', base: './src/content/faq' }),
  schema: z.object({
    question: z.string(),
    order: z.number().int().min(0),
  }),
});

export const collections = { site, features, testimonials, pricing, faq };
```

Note the `({ image })` shape on schemas that include images — that's how you get `image()` to resolve to `ImageMetadata` for use with `<Image />`.

## Reading content in components

Always inside the section component, not the page:

```astro
---
// src/components/sections/Features.astro
import { getCollection } from 'astro:content';

const features = (await getCollection('features'))
  .sort((a, b) => a.data.order - b.data.order);
---
```

For a single-entry collection like `site`:

```astro
---
import { getEntry } from 'astro:content';
const settings = await getEntry('site', 'settings');
if (!settings) throw new Error('Site settings not found');
const { name, tagline, nav } = settings.data;
---
```

The `if (!settings) throw` is the senior move — `getEntry` returns `undefined` if the entry's missing. Don't `settings!.data.name` it; throw a useful error so a missing file fails the build with a clear message instead of crashing at runtime.

## Rendering Markdown body (FAQ answers)

```astro
---
import { getCollection, render } from 'astro:content';
const items = (await getCollection('faq')).sort((a, b) => a.data.order - b.data.order);
---

<dl>
  {items.map(async (item) => {
    const { Content } = await render(item);
    return (
      <>
        <dt class="font-semibold">{item.data.question}</dt>
        <dd class="prose prose-sm mt-2"><Content /></dd>
      </>
    );
  })}
</dl>
```

If you're using prose styling here, the typography plugin needs to be installed (see `tailwind-setup.md`).

## Seed content guidance

When generating placeholder content for a company:

- **Don't write "Lorem ipsum."** Write plausible copy that fits the company's actual industry. The user will likely keep some of it.
- **Three features beats five mediocre ones.** Pick the strongest angles.
- **Testimonials need real-sounding names and titles.** "John Smith, Customer" is junior. "Mireia Pons, Head of Operations at Logistix" is what you want.
- **Pricing tiers: three, with the middle one highlighted.** Industry default for a reason.
- **FAQ: 4–6 entries.** Cover pricing, onboarding, cancellation, integrations. Don't pad.

## When to deviate from this structure

- **One-pager with no testimonials/pricing:** Skip those collections entirely. Don't create empty schemas "in case".
- **Multi-page site (about, contact, blog):** Add a `pages` collection with Markdown for long-form content. Hero/features stay structured.
- **i18n:** Add a locale field per entry and filter in components, or use Astro's i18n routing — query the MCP for current best practice (`Astro:search_astro_docs` → `"i18n routing content collections"`).
