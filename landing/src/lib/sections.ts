/**
 * The six sections of the home page, in order, with the anchor each one lives at.
 *
 * The navigation, the anchors and the content keys come from this single list, so a
 * section cannot end up in the menu without a heading to jump to, or the other way
 * round (`landing/CONTENT.md` "Site structure"). The keys are checked against the
 * content schema wherever they are used to read it.
 */
export const SECTIONS = [
  { key: 'idea', anchor: 'idea' },
  { key: 'whatItIs', anchor: 'what-it-is' },
  { key: 'howItWorks', anchor: 'how-it-works' },
  { key: 'runItYourself', anchor: 'run-it-yourself' },
  { key: 'checkItYourself', anchor: 'check-it-yourself' },
  { key: 'openSource', anchor: 'open-source' },
] as const;

export type SectionKey = (typeof SECTIONS)[number]['key'];

export const SECTION_KEYS = SECTIONS.map((section) => section.key) as [
  SectionKey,
  ...SectionKey[],
];

export function anchorOf(key: SectionKey): string {
  const section = SECTIONS.find((candidate) => candidate.key === key);
  if (section === undefined) throw new Error(`landing: no anchor for the section ${key}`);
  return section.anchor;
}
