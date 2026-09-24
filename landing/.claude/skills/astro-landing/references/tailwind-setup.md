# Tailwind v4 setup for Astro

This is the current path. The `@astrojs/tailwind` integration is **legacy** (Tailwind v3 only) — don't use it. Tailwind v4 ships as a Vite plugin.

## Install

```bash
npx astro add tailwind --yes
```

This runs the Astro CLI which installs `@tailwindcss/vite` and `tailwindcss`, wires the plugin into `astro.config.mjs`, and creates `src/styles/global.css` with `@import "tailwindcss";`.

If you're unsure whether the CLI did everything (or you're on an Astro version where `astro add tailwind` behaves differently), query the MCP: `Astro:search_astro_docs` with `"add tailwind vite plugin"`.

## Verify the wiring

`astro.config.mjs` should look like this:

```js
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://example.com',
  integrations: [sitemap()],
  vite: { plugins: [tailwindcss()] },
});
```

`src/styles/global.css`:

```css
@import "tailwindcss";
```

The CSS file must be imported once from a component that's on every page — the base layout:

```astro
---
// src/layouts/BaseLayout.astro
import '../styles/global.css';
---
```

## Design tokens with `@theme`

Tailwind v4 uses `@theme` in CSS for tokens. This is where the brand color, fonts, and any custom spacing live. Edit this file, not random utility classes.

```css
@import "tailwindcss";

@theme {
  /* Brand */
  --color-accent-50:  oklch(0.97 0.02 250);
  --color-accent-100: oklch(0.93 0.05 250);
  --color-accent-200: oklch(0.87 0.10 250);
  --color-accent-300: oklch(0.78 0.15 250);
  --color-accent-400: oklch(0.68 0.20 250);
  --color-accent-500: oklch(0.58 0.22 250);  /* primary */
  --color-accent-600: oklch(0.50 0.20 250);
  --color-accent-700: oklch(0.42 0.17 250);
  --color-accent-800: oklch(0.34 0.13 250);
  --color-accent-900: oklch(0.26 0.09 250);

  /* Typography */
  --font-sans: 'Inter', ui-sans-serif, system-ui, sans-serif;
  --font-display: 'Inter', ui-sans-serif, system-ui, sans-serif;

  /* Container */
  --container-max: 80rem;  /* 1280px */
}
```

Defining `--color-accent-*` automatically generates `bg-accent-500`, `text-accent-600`, `border-accent-200`, etc. across all utilities. That's the trick — you get a full Tailwind palette under your brand name from the CSS variables alone.

Use `oklch()` for color tokens. It's perceptually uniform, so the lighter/darker shades feel evenly spaced. If the user gives you a hex, convert it to `oklch` (or ask the MCP / a quick search if you don't have the conversion memorized).

## Loading custom fonts

Two options:

**1. Self-hosted via `@font-face` in `global.css`** (best for performance — no third-party request):

```css
@font-face {
  font-family: 'Inter';
  src: url('/fonts/inter-variable.woff2') format('woff2-variations');
  font-weight: 100 900;
  font-display: swap;
}

@import "tailwindcss";

@theme {
  --font-sans: 'Inter', ui-sans-serif, system-ui, sans-serif;
}
```

Drop the woff2 in `public/fonts/`.

**2. Google Fonts via `<link>` in BaseLayout** (faster to set up, slower to render):

```astro
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
```

Prefer option 1 for production. Option 2 is fine for prototypes.

## Dark mode

Tailwind v4 dark mode is opt-in. Add this to `global.css`:

```css
@custom-variant dark (&:where(.dark, .dark *));
```

Then toggle the `dark` class on `<html>`. Use a small island for the toggle if needed (see `component-patterns.md`).

For automatic system preference, add to `BaseLayout.astro` head (inline, before paint, to avoid FOUC):

```html
<script is:inline>
  const stored = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  if (stored === 'dark' || (!stored && prefersDark)) {
    document.documentElement.classList.add('dark');
  }
</script>
```

`is:inline` keeps it from being processed/bundled — it must run before paint.

## Typography plugin (for Markdown content)

If the landing renders any Markdown (a long-form "About" section, a blog later), add `@tailwindcss/typography`:

```bash
npm install -D @tailwindcss/typography
```

```css
@import "tailwindcss";
@plugin "@tailwindcss/typography";
```

Then wrap rendered Markdown in a `<div class="prose">`. Don't add this plugin if the landing has no Markdown — it's bloat otherwise.

## What not to do

- Don't install both `@astrojs/tailwind` and `@tailwindcss/vite` — they conflict. Tailwind v4 = only `@tailwindcss/vite`.
- Don't create a `tailwind.config.js` — v4 doesn't use one. Configuration lives in CSS via `@theme`.
- Don't put Tailwind classes in `public/` HTML files — Tailwind won't scan them.
- Don't use arbitrary values for the brand color (`bg-[#3b82f6]`). Define `--color-accent-500` and use `bg-accent-500`.
