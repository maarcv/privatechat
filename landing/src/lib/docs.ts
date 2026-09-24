/**
 * The parts of the site that quote the repository are read from the repository, at
 * build time, and never copied into this project by hand.
 *
 * `landing/CONTENT.md` requires the security page to reproduce the two lists of
 * `docs/spec.md` §1 and the table of `docs/threat-model.md` literally, and the site must not drift from them. Parsing the
 * documents is what makes that mechanical: if a list, a table or a heading moves, the
 * build fails here instead of the site quietly going stale.
 */
import specSource from '../../../docs/spec.md?raw';
import threatModelSource from '../../../docs/threat-model.md?raw';
import readmeSource from '../../../README.md?raw';

export interface DocsTable {
  readonly columns: readonly string[];
  readonly rows: readonly (readonly string[])[];
}

export interface SpecHeader {
  readonly version: string;
  readonly updated: string;
}

function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(
      `landing: ${what} was not found in the repository documents. The site is built ` +
        'from them (src/lib/docs.ts); update the parser or restore the document.',
    );
  }
  return value;
}

/** The bullet list that follows `marker`, one entry per `- ` line. */
function bulletsAfter(source: string, marker: string): string[] {
  const start = source.indexOf(marker);
  if (start === -1) return [];
  const bullets: string[] = [];
  for (const line of source.slice(start + marker.length).split('\n')) {
    if (line.startsWith('- ')) bullets.push(line.slice(2).trim());
    else if (bullets.length > 0) break;
  }
  return bullets;
}

/** The first Markdown table that follows `marker`, header row included. */
function tableAfter(source: string, marker: string): DocsTable | undefined {
  const start = source.indexOf(marker);
  if (start === -1) return undefined;
  const rows: string[][] = [];
  for (const line of source.slice(start + marker.length).split('\n')) {
    if (line.startsWith('|')) rows.push(cells(line));
    else if (rows.length > 0) break;
  }
  const [columns, , ...body] = rows;
  if (columns === undefined || body.length === 0) return undefined;
  return { columns, rows: body };
}

function cells(row: string): string[] {
  return row
    .replace(/^\||\|$/g, '')
    .split(/(?<!\\)\|/)
    .map((cell) => cell.trim().replace(/\\\|/g, '|'));
}

/** The paragraph that follows a `## ` heading. */
function paragraphAfter(source: string, heading: string): string | undefined {
  const start = source.indexOf(heading);
  if (start === -1) return undefined;
  return source
    .slice(start + heading.length)
    .split('\n')
    .find((line) => line.trim() !== '')
    ?.trim();
}

/** Version and date of the specification this site was built from. */
export const specHeader: SpecHeader = (() => {
  const match = /^Version: (.+?) · Updated: (\d{4}-\d{2}-\d{2})/m.exec(specSource);
  const [, version, updated] = need(match ?? undefined, 'the header of docs/spec.md');
  return { version: need(version, 'the version in the header of docs/spec.md'), updated: need(updated, 'the date in the header of docs/spec.md') };
})();

/** The project's phase, as the repository README states it. */
export const projectStatus: string = need(
  /^\*\*Status:\*\* (.+)$/m.exec(readmeSource)?.[1],
  'the `**Status:**` line of README.md',
);

/** `docs/spec.md` §1 "What it promises", verbatim. */
export const promises: readonly string[] = (() => {
  const items = bulletsAfter(specSource, '**What it promises**');
  if (items.length === 0) need(undefined, 'the list "What it promises" of docs/spec.md §1');
  return items;
})();

/**
 * `docs/spec.md` §1 "What it does not promise", verbatim. Since audit G it is the single
 * list: `docs/threat-model.md` "Accepted limitations" only points at it.
 */
export const acceptedLimitations: readonly string[] = (() => {
  const items = bulletsAfter(specSource, '**What it does not promise');
  if (items.length === 0) need(undefined, 'the list "What it does not promise" of docs/spec.md §1');
  return items;
})();

/** The adversaries table, three columns, as `docs/spec.md` §2 defines it. */
export const adversaries: DocsTable = need(
  tableAfter(threatModelSource, '## Adversaries and mitigations'),
  'the adversaries table of docs/threat-model.md',
);

/** `docs/spec.md` §2 "Outside the model", one sentence. */
export const outsideTheModel: string = need(
  paragraphAfter(threatModelSource, '## Outside the model'),
  'the section "Outside the model" of docs/threat-model.md',
);
