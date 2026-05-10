/**
 * Save hook — transparent encryption on save for .secret.md files.
 *
 * Registers a `vault.on('modify')` event listener that intercepts saves
 * for notes matching the configured encrypted suffix. On intercept:
 *   1. Read file content from vault
 *   2. Split frontmatter/body using splitFrontmatter()
 *   3. If body is already an encrypted ```ocke-v1 block, skip
 *   4. Encode body to UTF-8 bytes
 *   5. Build EncryptionContext
 *   6. Call cryptoEngine.encrypt(bodyBytes, cmkArn, 'aws-kms', context)
 *   7. Serialize the record to binary, then encode as ```ocke-v1 text block
 *   8. Combine: frontmatter + encrypted text block
 *   9. Write the combined text content to disk
 *  10. On failure: leave file unchanged, show error notice
 *
 * The encrypted content is stored as a text-based ```ocke-v1 fenced block
 * (base64-encoded binary), NOT as raw binary. This ensures Obsidian can
 * always open the file as a markdown note, and the CodeMirror widget can
 * render the decrypted content visually.
 */

import type { Plugin, TAbstractFile, TFile, Vault } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';
import { splitFrontmatter } from '../utils/frontmatter';
import { serialize } from '../format/serializer';
import { encodeInlineBlock } from '../format/inline-codec';
import { atomicFileWrite } from '../utils/atomic-write';
import { FORMAT_VERSION } from '../constants';
import { PluginError } from '../providers/errors';
import { showErrorNotice, showNotice } from '../ui/notices';

/** Regex to detect an existing ```ocke-v1 block */
const ENCRYPTED_BLOCK_REGEX = /^```ocke-v1\n[\s\S]*?\n```$/;

/**
 * A set of file paths currently being processed by the save hook.
 * Used to prevent re-entrant processing when the write triggers
 * another modify event.
 */
const processingPaths = new Set<string>();

/**
 * Register the save hook that transparently encrypts suffix-matching notes on save.
 */
export function registerSaveHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.vault.on('modify', (file: TAbstractFile) => {
      if (!isFile(file)) {
        return;
      }

      const settings = getSettings();

      if (!matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
        return;
      }

      if (processingPaths.has(file.path)) {
        return;
      }

      handleSaveEncryption(file, plugin.app.vault, cryptoEngine, settings).catch(
        () => {}
      );
    })
  );
}

/**
 * Handle the encryption of a suffix-matching note on save.
 */
async function handleSaveEncryption(
  file: TFile,
  vault: Vault,
  cryptoEngine: CryptoEngine,
  settings: PluginSettings
): Promise<void> {
  processingPaths.add(file.path);

  try {
    // 1. Read file content from vault (always text)
    const content = await vault.read(file);

    // 2. Split frontmatter/body
    const { frontmatter, body } = splitFrontmatter(content);

    // 3. Check if body is already an encrypted ```ocke-v1 block — skip
    if (isAlreadyEncrypted(body)) {
      return;
    }

    // 4. If body is empty, skip encryption
    if (body.trim() === '') {
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

    // 8. Encrypt
    const record = await cryptoEngine.encrypt(
      bodyBytes,
      settings.awsCmkArn,
      'aws-kms',
      context
    );

    // 9. Serialize to binary, then encode as text ```ocke-v1 block
    const serializedBytes = serialize(record);
    const encryptedTextBlock = encodeInlineBlock(serializedBytes);

    // 10. Combine: frontmatter + encrypted text block
    const combined = frontmatter
      ? frontmatter + encryptedTextBlock + '\n'
      : encryptedTextBlock + '\n';

    // 11. Write as text content to disk
    const combinedBytes = encoder.encode(combined);
    await atomicFileWrite(vault, file.path, combinedBytes);
  } catch (err) {
    if (err instanceof PluginError) {
      showErrorNotice(err);
    } else {
      showNotice(
        `Encryption failed for "${file.path}": ${err instanceof Error ? err.message : String(err)}`
      );
    }
  } finally {
    processingPaths.delete(file.path);
  }
}

/**
 * Check if the body is already an encrypted ```ocke-v1 block.
 */
function isAlreadyEncrypted(body: string): boolean {
  return ENCRYPTED_BLOCK_REGEX.test(body.trim());
}

/**
 * Type guard to check if a TAbstractFile is a TFile.
 */
function isFile(file: TAbstractFile): file is TFile {
  return 'extension' in file;
}
