/**
 * The parts of the site that quote the repository are read from the repository, at
 * build time, and never copied into this project by hand.
 *
 * `landing/CONTENT.md` requires the security page to reproduce `docs/spec.md` §1 and
 * `docs/threat-model.md` literally, and the site must not drift from them. Parsing the
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
 * `docs/threat-model.md` "Accepted limitations", verbatim: the nine items of
 * `docs/spec.md` §1 "What it does not promise" followed by the three the threat model
 * adds. The site shows the longer list, so it checks here that it really does start
 * with the shorter one.
 */
export const acceptedLimitations: readonly string[] = (() => {
  const accepted = bulletsAfter(threatModelSource, '## Accepted limitations, publicly documented');
  const promised = bulletsAfter(specSource, '**What it does not promise');
  if (accepted.length === 0) need(undefined, 'the list "Accepted limitations" of docs/threat-model.md');
  const divergent = promised.findIndex((item, index) => accepted[index] !== item);
  if (promised.length === 0 || divergent !== -1) {
    throw new Error(
      'landing: docs/threat-model.md "Accepted limitations" no longer starts with ' +
        `docs/spec.md §1 "What it does not promise" (item ${divergent + 1} differs). ` +
        'The security page quotes both; resolve the divergence in the documents first.',
    );
  }
  return accepted;
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
