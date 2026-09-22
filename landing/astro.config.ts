import { defineConfig } from 'astro/config';

import sitemap from '@astrojs/sitemap';
import tailwindcss from '@tailwindcss/vite';

import { DEFAULT_LOCALE, LOCALES, SITE_URL } from './src/lib/i18n';

// https://astro.build/config
export default defineConfig({
  // No domain has been decided yet, so the site uses the reserved TLD `.invalid`
  // for the same reason `DEFAULT_SERVER_URL` does (spec 000 R4): a build that is
  // published by mistake links nowhere real.
  site: SITE_URL,

  i18n: {
    locales: [...LOCALES],
    defaultLocale: DEFAULT_LOCALE,
    // Every page lives under a language prefix; `src/pages/index.astro` is the only
    // page at the root and it sends the reader to the default language.
    routing: { prefixDefaultLocale: true, redirectToDefaultLocale: false },
  },

  integrations: [
    sitemap({
      // `/` only forwards to the default language and is marked `noindex`.
      filter: (page) => new URL(page).pathname !== '/',
      i18n: {
        defaultLocale: DEFAULT_LOCALE,
        locales: Object.fromEntries(LOCALES.map((locale) => [locale, locale])),
      },
    }),
  ],

  vite: {
    plugins: [tailwindcss()],
    // The security page is built from `docs/` at the root of the repository
    // (src/lib/docs.ts), one directory above this project.
    server: { fs: { allow: ['..'] } },
  },
});
