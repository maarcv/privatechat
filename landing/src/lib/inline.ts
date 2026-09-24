/**
 * The smallest possible renderer for the inline Markdown that appears inside the
 * repository documents the site copies: code spans, bold and italic. It exists so the
 * site can reproduce those sentences verbatim without pulling a Markdown library in
 * for three constructs, and it escapes before it marks up, so the source documents can
 * never inject HTML into the page.
 */

const ESCAPED: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
};

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"]/g, (character) => ESCAPED[character] ?? character);
}

/** Escaped HTML for one line of inline Markdown. Block constructs are not supported. */
export function inlineMarkdown(text: string): string {
  return text
    .split(/(`[^`]+`)/g)
    .map((part) =>
      part.startsWith('`') && part.endsWith('`') && part.length > 2
        ? `<code>${escapeHtml(part.slice(1, -1))}</code>`
        : emphasis(escapeHtml(part)),
    )
    .join('');
}

function emphasis(escaped: string): string {
  return escaped
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}
