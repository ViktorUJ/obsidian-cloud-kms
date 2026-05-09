/**
 * Suffix-based file matching for transparent encryption.
 *
 * Determines whether a file should be transparently encrypted based on its
 * file name suffix (for notes) or extension pattern (for attachments).
 */

import { ENCRYPTED_NOTE_SUFFIX_DEFAULT } from "../constants";

/**
 * Check if a file name ends with the configured encrypted note suffix.
 * Uses case-sensitive exact suffix match on the full file name including extension.
 *
 * @param fileName - The full file name (e.g. "notes.secret.md")
 * @param suffix - The suffix to match (e.g. ".secret.md")
 * @returns true if the file name ends with the suffix (case-sensitive)
 *
 * @example
 * matchesEncryptedSuffix("notes.secret.md", ".secret.md") // true
 * matchesEncryptedSuffix("notes.Secret.md", ".secret.md") // false
 * matchesEncryptedSuffix("secret.md", ".secret.md")       // true
 * matchesEncryptedSuffix(".secret.md", ".secret.md")      // true
 */
export function matchesEncryptedSuffix(
  fileName: string,
  suffix: string = ENCRYPTED_NOTE_SUFFIX_DEFAULT
): boolean {
  if (!fileName || !suffix) {
    return false;
  }
  return fileName.endsWith(suffix);
}

/** Supported encrypted attachment extensions (case-insensitive) */
const ENCRYPTED_ATTACHMENT_EXTENSIONS = [".enc.png", ".enc.jpg", ".enc.pdf"];

/**
 * Check if a file name matches an encrypted attachment pattern.
 * Uses case-insensitive matching for `.enc.png`, `.enc.jpg`, `.enc.pdf`.
 *
 * @param fileName - The full file name (e.g. "screenshot.enc.png")
 * @returns true if the file name ends with a recognized encrypted attachment extension
 *
 * @example
 * matchesEncryptedAttachment("screenshot.enc.png") // true
 * matchesEncryptedAttachment("photo.ENC.JPG")      // true
 * matchesEncryptedAttachment("doc.enc.pdf")        // true
 * matchesEncryptedAttachment("notes.secret.md")    // false
 */
export function matchesEncryptedAttachment(fileName: string): boolean {
  if (!fileName) {
    return false;
  }
  const lowerName = fileName.toLowerCase();
  return ENCRYPTED_ATTACHMENT_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
}
