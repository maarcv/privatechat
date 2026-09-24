/**
 * How the accepted limitations are grouped on the security page.
 *
 * `landing/CONTENT.md` requires every sentence of `docs/spec.md` §1 "What it does not
 * promise" to appear verbatim, grouped for reading. The sentences themselves come
 * from the document (`src/lib/docs.ts`); which group each one belongs to is structure,
 * so it lives here and not in the translated content. Each key is a substring that
 * must match exactly one sentence, and `src/lib/security.ts` fails the build if a key
 * matches none, matches more than one, or if a sentence ends up in no group.
 */
export const LIMIT_GROUPS = [
  {
    id: 'device',
    match: [
      'compromised device',
      'not deniable',
      'any of their processes can read the data files',
      'Reinstalling the app',
      'Two devices of one person are two members',
    ],
  },
  {
    id: 'channel-key',
    match: [
      'depends on `K_ch`',
      'the new channel will leak again',
      'The per-channel quota protects the server',
    ],
  },
  {
    id: 'server',
    match: [
      'can delete or delay messages',
      'from which IP and at what time',
      'By default new channels go to the server',
      'No push notifications in v1',
    ],
  },
  {
    id: 'platform',
    match: ['The app store and the operating system'],
  },
] as const;

export type LimitGroupId = (typeof LIMIT_GROUPS)[number]['id'];

export const LIMIT_GROUP_IDS = LIMIT_GROUPS.map((group) => group.id) as [
  LimitGroupId,
  ...LimitGroupId[],
];
