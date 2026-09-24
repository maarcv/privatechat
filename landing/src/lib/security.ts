/**
 * The security page, assembled from the repository documents.
 *
 * `landing/CONTENT.md`: this page is copied from the docs, not rewritten. Everything
 * quoted here therefore comes from `src/lib/docs.ts`; this module only arranges it.
 */
import { acceptedLimitations } from './docs';
import { LIMIT_GROUPS, type LimitGroupId } from './limits';

export interface LimitGroup {
  readonly id: LimitGroupId;
  readonly items: readonly string[];
}

/**
 * The accepted limitations, in the order of the groups, with every sentence kept and
 * used exactly once. A mismatch is a build error: the grouping in `src/lib/limits.ts`
 * has fallen behind `docs/spec.md` §1.
 */
export function groupedLimitations(): readonly LimitGroup[] {
  const used = new Map<string, string>();
  const groups = LIMIT_GROUPS.map((group) => ({
    id: group.id,
    items: group.match.map((key) => {
      const found = acceptedLimitations.filter((item) => item.includes(key));
      const [item] = found;
      if (item === undefined || found.length > 1) {
        throw new Error(
          `landing: the accepted limitation matching ${JSON.stringify(key)} was found ` +
            `${found.length} times in docs/spec.md §1; update src/lib/limits.ts.`,
        );
      }
      const owner = used.get(item);
      if (owner !== undefined) {
        throw new Error(
          `landing: the accepted limitation matching ${JSON.stringify(key)} is already ` +
            `in the group "${owner}"; a sentence belongs to exactly one group.`,
        );
      }
      used.set(item, group.id);
      return item;
    }),
  }));

  const missing = acceptedLimitations.filter((item) => !used.has(item));
  if (missing.length > 0) {
    throw new Error(
      `landing: ${missing.length} accepted limitation(s) of docs/spec.md §1 are in ` +
        `no group of src/lib/limits.ts, and the page must keep every sentence: ` +
        missing.map((item) => JSON.stringify(item.slice(0, 60))).join(', '),
    );
  }
  return groups;
}
