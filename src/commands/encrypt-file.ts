/**
 * Phase 2 command: "Encrypt current file with AWS KMS"
 *
 * Registers an Obsidian command that encrypts the currently active file
 * (note or attachment) using envelope encryption (AES-256-GCM + AWS KMS DEK wrap).
 *
 * Flow:
 *   1. Get active file → if none, notice "No active file"
 *   2. Check if already encrypted (suffix match for notes, `.enc` for attachments) → notice
 *   3. Read file content from vault
 *   4. For notes (.md): split frontmatter/body, encrypt body, rename to add suffix, atomic write
 *   5. For attachments: encrypt entire content, rename to add `.enc` before extension, atomic write
 *   6. On any failure: restore original file name and content, show notice
 *   7. Use KMS_FILE_TIMEOUT_MS (30s) for the KMS call
 *
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
 */

import { Notice, Plugin, TFile } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import {
  FORMAT_VERSION,
  KMS_FILE_TIMEOUT_MS,
  NOTICE_DURATION_MS,
} from '../constants';
import { validateAwsKmsArn } from '../utils/arn-validator';
import { serialize } from '../format/serializer';
import { splitFrontmatter } from '../utils/frontmatter';
import { matchesEncryptedSuffix, matchesEncryptedAttachment } from '../policies/suffix-matcher';
import { encodeInlineBlock } from '../format/inline-codec';

/**
 * Register the "Encrypt current file with AWS KMS" command on the given plugin.
 *
 * Available from the command palette and file context menu for any file in the vault.
 *
 * @param plugin - The Obsidian plugin instance to register the command on
 * @param cryptoEngine - The CryptoEngine used for envelope encryption
 * @param getSettings - A function that returns the current plugin settings
 */
export function registerEncryptFileCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'encrypt-current-file-aws-kms',
    name: 'Encrypt current file with AWS KMS',
    callback: () => {
      executeEncryptFile(plugin, cryptoEngine, getSettings).catch(() => {
        // Errors are handled inside executeEncryptFile via notices
      });
    },
  });
}

/**
 * Determine if a file is a Markdown note.
 */
function isNote(file: TFile): boolean {
  return file.extension === 'md';
}

/**
 * Compute the encrypted file path for a note.
 * Inserts the configured suffix before the `.md` extension.
 * E.g., "notes/report.md" with suffix ".secret.md" → "notes/report.secret.md"
 */
function computeEncryptedNotePath(filePath: string, suffix: string): string {
  // The suffix already includes `.md`, so strip `.md` from original and append suffix
  if (filePath.endsWith('.md')) {
    return filePath.slice(0, -3) + suffix;
  }
  return filePath + suffix;
}

/**
 * Compute the encrypted file path for an attachment.
 * Inserts `.enc` before the extension.
 * E.g., "assets/screenshot.png" → "assets/screenshot.enc.png"
 */
function computeEncryptedAttachmentPath(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1) {
    // No extension — just append .enc
    return filePath + '.enc';
  }
  return filePath.slice(0, lastDot) + '.enc' + filePath.slice(lastDot);
}

/**
 * Execute the encrypt file flow.
 * All errors are caught and trigger rollback + notice display.
 */
async function executeEncryptFile(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): Promise<void> {
  // Step 1: Get active file
  const file = plugin.app.workspace.getActiveFile();
  if (!file) {
    new Notice('No active file', NOTICE_DURATION_MS);
    return;
  }

  const settings = getSettings();

  // Step 2: Check if already encrypted
  if (isNote(file)) {
    if (matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
      new Notice('File is already encrypted', NOTICE_DURATION_MS);
      return;
    }
  } else {
    if (matchesEncryptedAttachment(file.name)) {
      new Notice('File is already encrypted', NOTICE_DURATION_MS);
      return;
    }
  }

  // Validate CMK ARN
  const arnValidation = validateAwsKmsArn(settings.awsCmkArn);
  if (!arnValidation.valid) {
    new Notice(
      'Configure a valid AWS KMS Key ARN in plugin settings.',
      NOTICE_DURATION_MS
    );
    return;
  }

  const vault = plugin.app.vault;
  const originalPath = file.path;

  // Track state for rollback
  let renamed = false;
  let newPath = '';
  let originalContent: Uint8Array | null = null;

  try {
    if (isNote(file)) {
      // Step 4: Notes (.md) — split frontmatter/body, encrypt body, rename, atomic write
      const content = await vault.read(file);
      const encoder = new TextEncoder();
      originalContent = encoder.encode(content);

      const { frontmatter, body } = splitFrontmatter(content);

      // Encrypt the body
      const bodyBytes = encoder.encode(body);

      newPath = computeEncryptedNotePath(originalPath, settings.encryptedNoteSuffix);

      // Build encryption context using the NEW path (post-rename)
      const context: EncryptionContext = {
        vaultName: vault.getName(),
        filePath: newPath,
        formatVersion: FORMAT_VERSION,
      };

      // Encrypt with 30s timeout
      const record = await withTimeout(
        cryptoEngine.encrypt(bodyBytes, settings.awsCmkArn, 'aws-kms', context),
        KMS_FILE_TIMEOUT_MS
      );

      // Serialize the encrypted record
      const encryptedBinary = serialize(record);

      // Build the final file content: frontmatter (if any) + encrypted inline block
      const inlineBlock = encodeInlineBlock(encryptedBinary);
      const finalContent = (frontmatter ?? '') + inlineBlock;
      const finalBytes = encoder.encode(finalContent);

      // Rename the file first
      await vault.rename(file, newPath);
      renamed = true;

      // Write the encrypted content
      await vault.adapter.writeBinary(newPath, finalBytes);
    } else {
      // Step 5: Attachments — encrypt entire content, rename with `.enc`, atomic write
      const contentBuffer = await vault.readBinary(file);
      const contentBytes = new Uint8Array(contentBuffer);
      originalContent = new Uint8Array(contentBytes);

      newPath = computeEncryptedAttachmentPath(originalPath);

      // Build encryption context using the NEW path (post-rename)
      const context: EncryptionContext = {
        vaultName: vault.getName(),
        filePath: newPath,
        formatVersion: FORMAT_VERSION,
      };

      // Encrypt with 30s timeout
      const record = await withTimeout(
        cryptoEngine.encrypt(contentBytes, settings.awsCmkArn, 'aws-kms', context),
        KMS_FILE_TIMEOUT_MS
      );

      // Serialize the encrypted record to binary on-disk format
      const encryptedBinary = serialize(record);

      // Rename the file first
      await vault.rename(file, newPath);
      renamed = true;

      // Write the encrypted content
      await vault.adapter.writeBinary(newPath, encryptedBinary);
    }
  } catch (err) {
    // Step 6: Rollback on failure
    if (renamed) {
      try {
        // Rename back to original path
        const renamedFile = vault.getAbstractFileByPath(newPath);
        if (renamedFile && renamedFile instanceof TFile) {
          await vault.rename(renamedFile, originalPath);
        }
        // Restore original content if we have it
        if (originalContent) {
          await vault.adapter.writeBinary(originalPath, originalContent);
        }
      } catch {
        // Best-effort rollback
      }
    }

    const message = err instanceof Error ? err.message : 'File encryption failed';
    new Notice(`Encryption error: ${message}`, NOTICE_DURATION_MS);
  }
}

/**
 * Wrap a promise with a timeout. Rejects with a timeout error if the
 * promise does not resolve within the specified duration.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`KMS operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
