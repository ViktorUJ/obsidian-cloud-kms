/**
 * Save hook — transparent encryption on save.
 *
 * Registers a `vault.on('modify')` event listener that intercepts saves
 * for notes matching the configured encrypted suffix. On intercept:
 *   1. Read file content from vault
 *   2. Split frontmatter/body using splitFrontmatter()
 *   3. If body is already an encrypted block (starts with OCKE magic bytes), skip
 *   4. Encode body to UTF-8 bytes
 *   5. Build EncryptionContext
 *   6. Call cryptoEngine.encrypt(bodyBytes, cmkArn, 'aws-kms', context)
 *   7. Serialize the record to binary
 *   8. Combine: frontmatter (as UTF-8) + serialized encrypted block
 *   9. Atomic write the combined content to disk
 *  10. On failure: leave file unchanged, show error notice
 *
 * Infinite-loop prevention: after writing the encrypted file, the vault
 * fires another 'modify' event. The hook detects that the body is already
 * an encrypted block (starts with OCKE magic bytes) and skips re-encryption.
 * Additionally, a processingPaths set prevents re-entrant processing.
 */

import type { Plugin, TAbstractFile, TFile, Vault } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';
import { splitFrontmatter } from '../utils/frontmatter';
import { isMagicMatch } from '../format/parser';
import { serialize } from '../format/serializer';
import { atomicFileWrite } from '../utils/atomic-write';
import { MAGIC_BYTES, FORMAT_VERSION } from '../constants';
import { PluginError } from '../providers/errors';
import { showErrorNotice, showNotice } from '../ui/notices';

/**
 * A set of file paths currently being processed by the save hook.
 * Used to prevent re-entrant processing when the atomic write triggers
 * another modify event.
 */
const processingPaths = new Set<string>();

/**
 * Register the save hook that transparently encrypts suffix-matching notes on save.
 *
 * @param plugin - The Obsidian plugin instance (used for event registration lifecycle)
 * @param cryptoEngine - The CryptoEngine for envelope encryption
 * @param getSettings - Accessor for current plugin settings
 */
export function registerSaveHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.vault.on('modify', (file: TAbstractFile) => {
      // Only process files (not folders) — duck-type check for TFile
      if (!isFile(file)) {
        return;
      }

      const settings = getSettings();

      // Check if file matches the encrypted suffix
      if (!matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
        return;
      }

      // Prevent re-entrant processing
      if (processingPaths.has(file.path)) {
        return;
      }

      // Fire-and-forget the async encryption (Obsidian events are synchronous)
      handleSaveEncryption(file, plugin.app.vault, cryptoEngine, settings).catch(
        () => {
          // Errors are handled inside handleSaveEncryption
        }
      );
    })
  );
}

/**
 * Handle the encryption of a suffix-matching note on save.
 * Reads the file, splits frontmatter/body, encrypts the body, and writes
 * the encrypted result back atomically.
 *
 * On any failure, the file is left unchanged and an error notice is shown.
 */
async function handleSaveEncryption(
  file: TFile,
  vault: Vault,
  cryptoEngine: CryptoEngine,
  settings: PluginSettings
): Promise<void> {
  // Mark this path as being processed to prevent re-entrant triggers
  processingPaths.add(file.path);

  try {
    // 1. Read file content from vault
    const content = await vault.read(file);

    // 2. Split frontmatter/body
    const { frontmatter, body } = splitFrontmatter(content);

    // 3. Check if body is already encrypted (starts with OCKE magic bytes)
    if (isAlreadyEncrypted(body)) {
      return;
    }

    // 4. If body is empty, skip encryption (nothing to encrypt)
    if (body === '') {
      return;
    }

    // 5. Validate that a CMK ARN is configured
    if (!settings.awsCmkArn || settings.awsCmkArn.trim() === '') {
      showNotice(`Cannot encrypt "${file.path}": no CMK ARN configured`);
      return;
    }

    // 6. Encode body to UTF-8 bytes
    const encoder = new TextEncoder();
    const bodyBytes = encoder.encode(body);

    // 7. Build EncryptionContext
    const context: EncryptionContext = {
      vaultName: vault.getName(),
      filePath: file.path,
      formatVersion: FORMAT_VERSION,
    };

    // 8. Call cryptoEngine.encrypt
    const record = await cryptoEngine.encrypt(
      bodyBytes,
      settings.awsCmkArn,
      'aws-kms',
      context
    );

    // 9. Serialize the record to binary
    const serializedBlock = serialize(record);

    // 10. Combine: frontmatter (as UTF-8) + serialized encrypted block
    let combined: Uint8Array;
    if (frontmatter) {
      const frontmatterBytes = encoder.encode(frontmatter);
      combined = new Uint8Array(frontmatterBytes.length + serializedBlock.length);
      combined.set(frontmatterBytes, 0);
      combined.set(serializedBlock, frontmatterBytes.length);
    } else {
      combined = serializedBlock;
    }

    // 11. Atomic write the combined content to disk
    await atomicFileWrite(vault, file.path, combined);
  } catch (err) {
    // On failure: leave file unchanged, show error notice
    if (err instanceof PluginError) {
      showErrorNotice(err);
    } else {
      showNotice(
        `Encryption failed for "${file.path}": ${err instanceof Error ? err.message : String(err)}`
      );
    }
  } finally {
    // Always clear the processing flag
    processingPaths.delete(file.path);
  }
}

/**
 * Check if the body content is already an encrypted block.
 * Detects the OCKE magic bytes at the start of the body (as raw binary).
 *
 * When the file has been encrypted, the body portion (after frontmatter)
 * starts with the binary OCKE magic bytes (0x4F 0x43 0x4B 0x45).
 * Since vault.read() returns a string, the binary bytes appear as their
 * character code equivalents.
 */
function isAlreadyEncrypted(body: string): boolean {
  if (body.length < MAGIC_BYTES.length) {
    return false;
  }

  // Check if the first bytes of the body match the OCKE magic bytes.
  // Since the body is a string read from vault, the encrypted binary content
  // will appear as the raw byte values when interpreted as a string.
  // We encode the body start to check against magic bytes.
  const encoder = new TextEncoder();
  const bodyStart = encoder.encode(body.slice(0, 16));
  return isMagicMatch(bodyStart);
}

/**
 * Type guard to check if a TAbstractFile is a TFile.
 * Uses duck-typing (presence of 'extension' property) rather than instanceof
 * for better testability with mocks.
 */
function isFile(file: TAbstractFile): file is TFile {
  return 'extension' in file;
}
