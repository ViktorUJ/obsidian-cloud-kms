/**
 * Frontmatter detection and splitting utility.
 *
 * Detects YAML frontmatter blocks delimited by `---` at the start of a note
 * and splits the note into frontmatter + body components.
 *
 * Frontmatter rules:
 * - Starts with `---\n` at position 0
 * - Ends with `\n---\n` (or `\n---` at EOF)
 * - Frontmatter includes the `---` delimiters themselves (written back as-is)
 * - Body is everything after the closing `---\n`
 */

/**
 * Result of splitting a note into frontmatter and body.
 */
export interface FrontmatterSplitResult {
  /** The frontmatter block including `---` delimiters, or null if none detected. */
  frontmatter: string | null;
  /** The body content after the frontmatter, or the entire content if no frontmatter. */
  body: string;
}

/**
 * Split a note's content into frontmatter and body.
 *
 * Frontmatter is detected when the content starts with `---\n` at position 0
 * and a closing `\n---\n` (or `\n---` at EOF) is found.
 *
 * @param content - The full note content as a string
 * @returns The split result with frontmatter (or null) and body
 */
export function splitFrontmatter(content: string): FrontmatterSplitResult {
  // Frontmatter must start with `---\n` at position 0
  if (!content.startsWith('---\n')) {
    return { frontmatter: null, body: content };
  }

  // Search for the closing delimiter: `\n---\n` or `\n---` at EOF
  const searchStart = 4; // Skip the opening `---\n`
  const closingDelimiter = '\n---\n';
  const closingIndex = content.indexOf(closingDelimiter, searchStart);

  if (closingIndex !== -1) {
    // Found `\n---\n` — frontmatter includes up to and including `\n---\n`
    const frontmatterEnd = closingIndex + closingDelimiter.length;
    const frontmatter = content.slice(0, frontmatterEnd);
    const body = content.slice(frontmatterEnd);
    return { frontmatter, body };
  }

  // Check for `\n---` at EOF (no trailing newline after closing delimiter)
  const closingAtEof = '\n---';
  if (content.endsWith(closingAtEof) && content.length > searchStart + closingAtEof.length) {
    // The entire content is frontmatter with no body
    return { frontmatter: content, body: '' };
  }

  // No valid closing delimiter found — treat entire content as body
  return { frontmatter: null, body: content };
}
