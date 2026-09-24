/**
 * Every address the site links to, in one place.
 *
 * Links are not copy: they are the same in every language, so they live here and the
 * content files refer to them by name (`link: 'threatModel'`). Nothing on the site
 * points at a server, a download or a store, because none of those exist yet
 * (`landing/CONTENT.md`: no address until there is one).
 */
import { localePath, type Locale } from './i18n';
import { anchorOf, type SectionKey } from './sections';

const REPOSITORY = 'https://github.com/maarcv/privatechat';

function inRepository(path: string): string {
  return `${REPOSITORY}/blob/mvp/${path}`;
}

export const LINKS = {
  repository: REPOSITORY,
  spec: inRepository('docs/spec.md'),
  threatModel: inRepository('docs/threat-model.md'),
  auditLog: inRepository('docs/audit-log.md'),
  adrIndex: inRepository('docs/adr/README.md'),
  specs: inRepository('specs/README.md'),
  vectors: inRepository('specs/vectors/README.md'),
  agents: inRepository('AGENTS.md'),
  contributing: inRepository('.github/CONTRIBUTING.md'),
  securityPolicy: inRepository('.github/SECURITY.md'),
  licence: inRepository('LICENSE'),
  deploy: inRepository('deploy/README.md'),
} as const;

export type LinkName = keyof typeof LINKS;

export const LINK_NAMES = Object.keys(LINKS) as [LinkName, ...LinkName[]];

/**
 * Where an action in the content points: either an address of `LINKS` or a section of
 * the page the reader is on. The content schema accepts exactly one of the two.
 */
export interface Target {
  link?: LinkName;
  section?: SectionKey;
}

export function hrefOf(target: Target, locale: Locale): string {
  if (target.link !== undefined) return LINKS[target.link];
  if (target.section !== undefined) return `${localePath(locale)}#${anchorOf(target.section)}`;
  throw new Error('landing: an action points neither at a link nor at a section');
}
