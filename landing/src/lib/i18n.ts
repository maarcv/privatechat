/**
 * Languages of the site and the paths they live at.
 *
 * English is the source language; the other four are translations of the accepted
 * English text (`docs/spec.md` §9, `landing/CONTENT.md`). A language exists on the
 * site only once its content entries exist, so this list is the set of languages the
 * site may publish, not the set it currently publishes: `availableLocales()` in
 * `src/lib/content.ts` reports the latter.
 */
export const LOCALES = ['en', 'es', 'fr', 'ca', 'it'] as const;

export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = 'en';

/** Each language named in itself, for the language picker. */
export const LOCALE_NAMES: Record<Locale, string> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  ca: 'Català',
  it: 'Italiano',
};

/**
 * No domain has been decided yet (`landing/CONTENT.md`, open questions). Until there
 * is one the site uses the reserved TLD `.invalid` (RFC 2606), the same convention
 * `DEFAULT_SERVER_URL` follows (spec 000 R4).
 */
export const SITE_URL = 'https://privatechat.invalid';

export function isLocale(value: string | undefined): value is Locale {
  return value !== undefined && (LOCALES as readonly string[]).includes(value);
}

/** Absolute path of a page within a language, always with a trailing slash. */
export function localePath(locale: Locale, page = ''): string {
  return page === '' ? `/${locale}/` : `/${locale}/${page}/`;
}
