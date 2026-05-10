/**
 * Inline block encryption hook.
 *
 * Save hook: On every modify event, reads the file from disk.
 * If it contains ```secret blocks, encrypts them to ```ocke-v1 and writes back.
 * Then restores the editor to show ```secret (decrypted) content.
 *
 * This ensures:
 * - Disk ALWAYS has ```ocke-v1 (encrypted)
 * - Editor ALWAYS shows ```secret (decrypted, editable)
 * - Even during a crash, the disk state is encrypted
 */

import { Plugin, TAbstractFile, TFile, MarkdownView } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';
import { encodeInlineBlock } from '../format/inline-codec';
import { serialize } from '../format/serializer';
import { atomicFileWrite } from '../utils/atomic-write';
import { FORMAT_VERSION } from '../constants';
import { showErrorNotice, showNotice } from '../ui/notices';
import { PluginError } from '../providers/errors';

/**
 * Regex to find ```secret blocks.
 */
const SECRET_BLOCK_REGEX = /```secret\n([\s\S]*?)\n```/g;

/**
 * Set of file paths currently being processed.
 * Prevents re-entrant processing.
 */
const processingPaths = new Set<string>();

/**
 * Register the inline block save hook.
 */
export function registerInlineBlockSaveHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.vault.on('modify', (file: TAbstractFile) => {
      if (!isFile(file)) return;

      const settings = getSettings();

      // Skip .secret.md files — handled by full-file save hook
      if (matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
        return;
      }

      if (processingPaths.has(file.path)) return;

      handleInlineBlockEncryption(file, plugin, cryptoEngine, settings).catch(() => {});
    })
  );
}

/**
 * Encrypt ```secret blocks on disk, then restore editor to show decrypted content.
 */
async function handleInlineBlockEncryption(
  file: TFile,
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  settings: PluginSettings
): Promise<void> {
  processingPaths.add(file.path);

  try {
    // Read what's on disk
    const content = await plugin.app.vault.read(file);

    // Check for ```secret blocks
    SECRET_BLOCK_REGEX.lastIndex = 0;
    if (!SECRET_BLOCK_REGEX.test(content)) {
      return;
    }

    if (!settings.awsCmkArn || settings.awsCmkArn.trim() === '') {
      showNotice(`Cannot encrypt inline blocks in "${file.path}": no CMK ARN configured`);
      return;
    }

    SECRET_BLOCK_REGEX.lastIndex = 0;

    // Collect matches
    const matches: Array<{ fullMatch: string; content: string }> = [];
    let match: RegExpExecArray | null;
    while ((match = SECRET_BLOCK_REGEX.exec(content)) !== null) {
      matches.push({ fullMatch: match[0], content: match[1] });
    }

    // Encrypt each block
    let encryptedContent = content;
    for (const m of matches) {
      const encoder = new TextEncoder();
      const plaintextBytes = encoder.encode(m.content);

      const context: EncryptionContext = {
        vaultName: plugin.app.vault.getName(),
        filePath: file.path,
        formatVersion: FORMAT_VERSION,
      };

      const record = await cryptoEngine.encrypt(
        plaintextBytes,
        settings.awsCmkArn,
        'aws-kms',
        context
      );

      const serializedBytes = serialize(record);
      const inlineBlock = encodeInlineBlock(serializedBytes);

      encryptedContent = encryptedContent.replace(m.fullMatch, inlineBlock);
    }

    if (encryptedContent === content) return;

    // Write encrypted version to disk
    const encoder = new TextEncoder();
    await atomicFileWrite(plugin.app.vault, file.path, encoder.encode(encryptedContent));

    // Restore editor to show the decrypted (```secret) version
    // so the user can continue editing
    const activeView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
    if (activeView && activeView.file?.path === file.path) {
      // Only restore if editor still shows the decrypted content
      const editorContent = activeView.editor.getValue();
      if (editorContent === content) {
        // Editor still has ```secret — good, leave it
        // (Obsidian hasn't re-read the file yet)
      } else {
        // Obsidian re-read the encrypted file — put decrypted back
        activeView.editor.setValue(content);
      }
    }
  } catch (err) {
    if (err instanceof PluginError) {
      showErrorNotice(err);
    } else {
      showNotice(
        `Inline block encryption failed for "${file.path}": ${err instanceof Error ? err.message : String(err)}`
      );
    }
  } finally {
    processingPaths.delete(file.path);
  }
}

function isFile(file: TAbstractFile): file is TFile {
  return 'extension' in file;
}
