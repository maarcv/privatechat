import { getCollection, getEntry, type CollectionEntry } from 'astro:content';

import { LOCALES, type Locale } from './i18n';

/**
 * The languages the site actually publishes: those that already have their copy.
 *
 * English is the source and the other four are translated from the accepted English
 * text, so a language appears in the navigation and gets its routes only once its
 * content files exist. Adding the language to each folder of `src/content` is all it takes.
 */
export async function availableLocales(): Promise<Locale[]> {
  const translated = new Set((await getCollection('site')).map((entry) => entry.id));
  return LOCALES.filter((locale) => translated.has(locale));
}

function missing(collection: string, locale: Locale): Error {
  return new Error(`landing: src/content/${collection}/${locale}.json is missing`);
}

export async function getSite(locale: Locale): Promise<CollectionEntry<'site'>['data']> {
  const entry = await getEntry('site', locale);
  if (entry === undefined) throw missing('site', locale);
  return entry.data;
}

export async function getHome(locale: Locale): Promise<CollectionEntry<'home'>['data']> {
  const entry = await getEntry('home', locale);
  if (entry === undefined) throw missing('home', locale);
  return entry.data;
}

export async function getSecurity(locale: Locale): Promise<CollectionEntry<'security'>['data']> {
  const entry = await getEntry('security', locale);
  if (entry === undefined) throw missing('security', locale);
  return entry.data;
}
