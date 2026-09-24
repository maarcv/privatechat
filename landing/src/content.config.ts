import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

import { LIMIT_GROUP_IDS } from './lib/limits';
import { LINK_NAMES } from './lib/links';
import { SECTION_KEYS } from './lib/sections';

/**
 * All copy lives here, one JSON file per language, never inline in a component
 * (`landing/README.md`). Addresses are not copy: a link names an entry of
 * `src/lib/links.ts` instead of repeating a URL in five files.
 */
const action = z
  .object({
    label: z.string(),
    note: z.string().optional(),
    link: z.enum(LINK_NAMES).optional(),
    section: z.enum(SECTION_KEYS).optional(),
  })
  .refine(
    (value) => (value.link === undefined) !== (value.section === undefined),
    'an action points either at an address of src/lib/links.ts or at a section of the page',
  );

const point = z.object({
  title: z.string(),
  body: z.string(),
});

const list = z.object({
  title: z.string(),
  items: z.array(z.string()).nonempty(),
});

const section = z.object({
  navLabel: z.string(),
  title: z.string(),
  lead: z.string(),
});

const meta = z.object({
  title: z.string(),
  description: z.string(),
});

/** One entry per language, its id being the language code of `src/lib/i18n.ts`. */
function perLanguage(directory: string) {
  return glob({ pattern: '*.json', base: `./src/content/${directory}` });
}

const site = defineCollection({
  loader: perLanguage('site'),
  schema: z.object({
    name: z.string(),
    description: z.string(),
    nav: z.object({
      label: z.string(),
      menuLabel: z.string(),
      security: z.string(),
      repository: z.string(),
    }),
    languages: z.object({ label: z.string() }),
    status: z.object({ label: z.string() }),
    footer: z.object({
      note: z.string(),
      links: z.array(action).nonempty(),
    }),
    skipToContent: z.string(),
  }),
});

const home = defineCollection({
  loader: perLanguage('home'),
  schema: z.object({
    meta,
    idea: section.extend({
      points: z.array(point).nonempty(),
      actions: z.array(action).nonempty(),
    }),
    whatItIs: section.extend({
      points: z.array(point).nonempty(),
      limits: list,
    }),
    howItWorks: section.extend({
      // Four steps, in the order of `landing/CONTENT.md` §3; each one is drawn by the
      // illustration at the same index in `HowItWorks.astro`.
      steps: z.array(point).length(4),
      also: list,
    }),
    runItYourself: section.extend({
      points: z.array(point).nonempty(),
      actions: z.array(action).nonempty(),
    }),
    checkItYourself: section.extend({
      plannedLabel: z.string(),
      checks: z
        .array(point.extend({ action, planned: z.boolean().default(false) }))
        .nonempty(),
    }),
    openSource: section.extend({
      points: z.array(point).nonempty(),
      actions: z.array(action).nonempty(),
    }),
  }),
});

const security = defineCollection({
  loader: perLanguage('security'),
  schema: z.object({
    meta,
    title: z.string(),
    lead: z.string(),
    promises: z.object({ title: z.string(), lead: z.string() }),
    limits: z.object({
      title: z.string(),
      lead: z.string(),
      // One title per group of `src/lib/limits.ts`; the sentences themselves come from
      // `docs/threat-model.md` and are not repeated here.
      groups: z
        .array(z.object({ id: z.enum(LIMIT_GROUP_IDS), title: z.string() }))
        .length(LIMIT_GROUP_IDS.length),
    }),
    adversaries: z.object({ title: z.string(), lead: z.string() }),
    outside: z.object({ title: z.string() }),
    provenance: z.object({
      title: z.string(),
      lead: z.string(),
      versionLabel: z.string(),
      links: z.array(action).nonempty(),
    }),
    backToHome: z.string(),
  }),
});

export const collections = { site, home, security };
