/**
 * Phase 1 command: "Decrypt selection with AWS KMS"
 *
 * Decrypts an inline ocke-v1 encrypted block in the user's selection,
 * replacing it with the original plaintext in the editor buffer only.
 *
 * Flow:
 *   1. Get active editor → if none, notice "No active editor"
 *   2. Get selection → if empty, notice "No text selected"
 *   3. Try findInlineBlock(selection) → if null, notice "No valid encrypted block in selection"
 *   4. decodeInlineBlock(selection) → get binary bytes
 *   5. parse(binary) → get EncryptedFileRecord
 *   6. Build EncryptionContext from vault name + file path + record.version
 *   7. Call cryptoEngine.decrypt(record, context) → get plaintext bytes
 *   8. Decode plaintext bytes to UTF-8 string
 *   9. Replace selection with plaintext string (editor buffer only, not saved to disk)
 *  10. On PluginError with category 'integrity': notice "Integrity check failed" ≥5s
 *  11. On PluginError with category 'timeout': notice "Decryption request timed out" ≥5s
 *  12. On any other error: notice with provider error message ≥5s
 */

import { Notice, Plugin } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { findInlineBlock, decodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { PluginError } from '../providers/errors';
import { NOTICE_DURATION_MS } from '../constants';

/**
 * Register the "Decrypt selection with AWS KMS" command on the given plugin instance.
 *
 * @param plugin - The Obsidian Plugin instance to register the command on
 * @param cryptoEngine - The CryptoEngine used for decryption
 * @param getSettings - A function returning the current plugin settings
 */
export function registerDecryptSelectionCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'decrypt-selection-aws-kms',
    name: 'Decrypt selection with AWS KMS',
    editorCallback: async (editor, view) => {
      // 1. Active editor is guaranteed by editorCallback

      // 2. Get selection
      const selection = editor.getSelection();
      if (!selection || selection.length === 0) {
        new Notice('No text selected', NOTICE_DURATION_MS);
        return;
      }

      // 3. Check for a valid ocke-v1 inline block in the selection
      const blockInfo = findInlineBlock(selection);
      if (!blockInfo) {
        new Notice('No valid encrypted block in selection', NOTICE_DURATION_MS);
        return;
      }

      try {
        // 4. Decode the inline block to binary bytes
        const binaryData = decodeInlineBlock(selection);
        if (!binaryData) {
          new Notice('No valid encrypted block in selection', NOTICE_DURATION_MS);
          return;
        }

        // 5. Parse binary into EncryptedFileRecord
        const record = parse(binaryData);

        // 6. Build EncryptionContext from vault name + file path + record.version
        const file = view.file;
        const vaultName = plugin.app.vault.getName();
        const filePath = file ? file.path : '';

        const context: EncryptionContext = {
          vaultName,
          filePath,
          formatVersion: record.version,
        };

        // 7. Decrypt via CryptoEngine
        const plaintextBytes = await cryptoEngine.decrypt(record, context);

        // 8. Decode plaintext bytes to UTF-8 string
        const plaintext = new TextDecoder('utf-8').decode(plaintextBytes);

        // 9. Replace selection with plaintext (editor buffer only, not saved to disk)
        editor.replaceSelection(plaintext);
      } catch (err) {
        // 10–12. Error handling with appropriate notices (≥5s)
        if (err instanceof PluginError) {
          if (err.category === 'integrity') {
            new Notice('Integrity check failed', NOTICE_DURATION_MS);
          } else if (err.category === 'timeout') {
            new Notice('Decryption request timed out', NOTICE_DURATION_MS);
          } else {
            new Notice(err.message, NOTICE_DURATION_MS);
          }
        } else {
          const message = err instanceof Error ? err.message : 'Decryption failed';
          new Notice(message, NOTICE_DURATION_MS);
        }
      }
    },
  });
}
