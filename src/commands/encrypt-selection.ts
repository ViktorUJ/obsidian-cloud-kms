/**
 * Phase 1 command: "Encrypt selection with AWS KMS"
 *
 * Registers an Obsidian command that encrypts the current editor selection
 * using envelope encryption (AES-256-GCM + AWS KMS DEK wrap).
 *
 * Flow:
 *   1. Check active editor exists → if not, notice "No active editor"
 *   2. Get selection → if empty or > MAX_SELECTION_CHARS, notice with reason
 *   3. Check settings.awsCmkArn is valid → if not, notice "Configure CMK ARN"
 *   4. Encode selection to UTF-8 bytes
 *   5. Build EncryptionContext from vault name + file path + FORMAT_VERSION
 *   6. Call cryptoEngine.encrypt(bytes, cmkArn, 'aws-kms', context)
 *   7. Call serialize(record) to get binary
 *   8. Call encodeInlineBlock(binary) to get markdown string
 *   9. Replace selection with the inline block string
 *  10. On any error: leave selection unchanged, show notice ≥5s
 */

import { Notice, Plugin, MarkdownView } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION, MAX_SELECTION_CHARS, NOTICE_DURATION_MS } from '../constants';
import { validateAwsKmsArn } from '../utils/arn-validator';
import { serialize } from '../format/serializer';
import { encodeInlineBlock } from '../format/inline-codec';

/**
 * Register the "Encrypt selection with AWS KMS" command on the given plugin.
 *
 * @param plugin - The Obsidian plugin instance to register the command on
 * @param cryptoEngine - The CryptoEngine used for envelope encryption
 * @param getSettings - A function that returns the current plugin settings
 */
export function registerEncryptSelectionCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'encrypt-selection-aws-kms',
    name: 'Encrypt selection with AWS KMS',
    editorCheckCallback: (checking) => {
      // Command is available only when an active Markdown editor is focused
      const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
      if (!markdownView) {
        return false;
      }

      if (checking) {
        return true;
      }

      // Execute the encryption flow
      executeEncryptSelection(plugin, cryptoEngine, getSettings).catch(() => {
        // Errors are handled inside executeEncryptSelection via notices
      });

      return true;
    },
  });
}

/**
 * Execute the encrypt selection flow.
 * All errors are caught and displayed as Obsidian notices (≥5s).
 * The editor selection is never modified on failure.
 */
async function executeEncryptSelection(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): Promise<void> {
  try {
    // Step 1: Check active editor exists
    const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
    if (!markdownView) {
      new Notice('No active editor', NOTICE_DURATION_MS);
      return;
    }

    const editor = markdownView.editor;

    // Step 2: Get selection and validate length
    const selection = editor.getSelection();

    if (!selection || selection.length === 0) {
      new Notice('No text selected. Select text to encrypt.', NOTICE_DURATION_MS);
      return;
    }

    if (selection.length > MAX_SELECTION_CHARS) {
      new Notice(
        `Selection too large: ${selection.length} characters exceeds maximum of ${MAX_SELECTION_CHARS}.`,
        NOTICE_DURATION_MS
      );
      return;
    }

    // Step 3: Validate CMK ARN
    const settings = getSettings();
    const arnValidation = validateAwsKmsArn(settings.awsCmkArn);

    if (!arnValidation.valid) {
      new Notice(
        'Configure a valid AWS KMS Key ARN in plugin settings.',
        NOTICE_DURATION_MS
      );
      return;
    }

    // Step 4: Encode selection to UTF-8 bytes
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(selection);

    // Step 5: Build EncryptionContext
    const file = markdownView.file;
    const context: EncryptionContext = {
      vaultName: plugin.app.vault.getName(),
      filePath: file ? file.path : '',
      formatVersion: FORMAT_VERSION,
    };

    // Step 6: Encrypt via CryptoEngine
    const record = await cryptoEngine.encrypt(
      plaintextBytes,
      settings.awsCmkArn,
      'aws-kms',
      context
    );

    // Step 7: Serialize the record to binary
    const binary = serialize(record);

    // Step 8: Encode as inline block
    const inlineBlock = encodeInlineBlock(binary);

    // Step 9: Replace selection with the inline block
    editor.replaceSelection(inlineBlock);
  } catch (err) {
    // Step 10: On any error, leave selection unchanged and show notice
    const message = err instanceof Error ? err.message : 'Encryption failed';
    new Notice(`Encryption error: ${message}`, NOTICE_DURATION_MS);
  }
}
