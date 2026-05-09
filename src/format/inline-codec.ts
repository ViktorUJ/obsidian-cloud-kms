/**
 * Inline codec for Phase 1 manual commands.
 *
 * Encodes binary On-Disk Format data as base64 inside a fenced Markdown block:
 *
 * ```ocke-v1
 * <base64-encoded binary On-Disk Format>
 * ```
 *
 * And decodes it back to binary.
 */

import { PluginError } from '../providers/errors';

/** Opening fence marker for an inline encrypted block */
const FENCE_OPEN = '```ocke-v1\n';

/** Closing fence marker for an inline encrypted block */
const FENCE_CLOSE = '\n```';

/**
 * Regex to find the first ocke-v1 fenced block in text.
 * Matches: ```ocke-v1\n<content>\n```
 * Uses non-greedy match for content to find the first closing fence.
 */
const INLINE_BLOCK_REGEX = /```ocke-v1\n([\s\S]*?)\n```/;

/**
 * Encode binary data into a base64 inline fenced block.
 *
 * @param binaryData - The binary On-Disk Format bytes to encode
 * @returns A string containing the fenced block with base64-encoded content
 */
export function encodeInlineBlock(binaryData: Uint8Array): string {
  const base64 = uint8ArrayToBase64(binaryData);
  return `${FENCE_OPEN}${base64}${FENCE_CLOSE}`;
}

/**
 * Decode an inline fenced block back to binary data.
 *
 * Detects the `ocke-v1` fence markers in the provided text, extracts the
 * base64 content, and decodes it to a Uint8Array.
 *
 * @param text - Text that should contain an ocke-v1 fenced block
 * @returns The decoded binary data, or null if no valid block is found
 * @throws PluginError with category 'format' if base64 content is malformed
 */
export function decodeInlineBlock(text: string): Uint8Array | null {
  const match = INLINE_BLOCK_REGEX.exec(text);
  if (!match) {
    return null;
  }

  const base64Content = match[1].trim().replace(/\s/g, '');
  if (base64Content.length === 0) {
    return null;
  }

  return base64ToUint8Array(base64Content);
}

/**
 * Find the first ocke-v1 fenced block in a larger text.
 *
 * @param text - The text to search for an inline block
 * @returns The position and raw content of the block, or null if not found
 */
export function findInlineBlock(
  text: string
): { start: number; end: number; content: string } | null {
  const match = INLINE_BLOCK_REGEX.exec(text);
  if (!match) {
    return null;
  }

  const start = match.index;
  const end = start + match[0].length;
  const content = match[1];

  return { start, end, content };
}

/**
 * Convert a Uint8Array to a base64 string using Buffer (Node.js).
 */
function uint8ArrayToBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

/**
 * Convert a base64 string to a Uint8Array using Buffer (Node.js).
 *
 * @throws PluginError with category 'format' if the base64 string is malformed
 */
function base64ToUint8Array(base64: string): Uint8Array {
  // Validate base64 characters before decoding
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
    throw new PluginError(
      'Malformed base64 content in ocke-v1 block',
      'format'
    );
  }

  const buffer = Buffer.from(base64, 'base64');

  // Buffer.from with 'base64' silently ignores invalid chars and may produce
  // an empty buffer for completely invalid input. Check for that case.
  if (buffer.length === 0 && base64.length > 0) {
    throw new PluginError(
      'Malformed base64 content in ocke-v1 block',
      'format'
    );
  }

  return new Uint8Array(buffer);
}
