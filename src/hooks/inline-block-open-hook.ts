/**
 * Inline block open hook — decrypts ```ocke-v1 blocks in the editor on file open.
 *
 * Uses multiple strategies to detect when a file with encrypted blocks is opened
 * and replaces them with ```secret blocks for editing.
 */

import { Plugin, MarkdownView } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION } from '../constants';
import { decodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';

const ENCRYPTED_BLOCK_REGEX = /```ocke-v1\n([\s\S]*?)\n```/g;

/** Tracks files already decrypted in this session to avoid re-processing */
const decryptedInSession = new Set<string>();

export function registerInlineBlockOpenHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  const tryDecrypt = async () => {
    const settings = getSettings();
    if (!settings.autoDecryptBlocks) return;

    const activeFile = plugin.app.workspace.getActiveFile();
    if (!activeFile) return;

    if (matchesEncryptedSuffix(activeFile.name, settings.encryptedNoteSuffix)) return;

    // Find the active markdown editor
    const activeLeaf = plugin.app.workspace.activeLeaf;
    if (!activeLeaf) return;

    const view = activeLeaf.view;
    if (!(view instanceof MarkdownView)) return;
    if (view.file?.path !== activeFile.path) return;

    const editor = view.editor;
    const content = editor.getValue();
    if (!content || content.length === 0) return;

    ENCRYPTED_BLOCK_REGEX.lastIndex = 0;
    if (!ENCRYPTED_BLOCK_REGEX.test(content)) return;

    // Skip if already decrypted in this session (prevents loops)
    const contentHash = activeFile.path + ':' + content.length;
    if (decryptedInSession.has(contentHash)) return;
    decryptedInSession.add(contentHash);

    ENCRYPTED_BLOCK_REGEX.lastIndex = 0;
    const matches: Array<{ fullMatch: string; base64Content: string }> = [];
    let match: RegExpExecArray | null;
    while ((match = ENCRYPTED_BLOCK_REGEX.exec(content)) !== null) {
      matches.push({ fullMatch: match[0], base64Content: match[1] });
    }

    let result = content;
    let anyDecrypted = false;

    for (const m of matches) {
      try {
        const fullBlock = '```ocke-v1\n' + m.base64Content + '\n```';
        const binaryData = decodeInlineBlock(fullBlock);
        if (!binaryData) continue;

        const record = parse(binaryData);
        const context: EncryptionContext = {
          vaultName: plugin.app.vault.getName(),
          filePath: activeFile.path,
          formatVersion: FORMAT_VERSION,
        };

        const plaintextBytes = await cryptoEngine.decrypt(record, context);
        const plaintext = new TextDecoder().decode(plaintextBytes);
        const secretBlock = '```secret\n' + plaintext + '\n```';
        result = result.replace(m.fullMatch, secretBlock);
        anyDecrypted = true;
      } catch {
        continue;
      }
    }

    if (anyDecrypted) {
      editor.setValue(result);
    }
  };

  // Strategy 1: file-open event
  plugin.registerEvent(
    plugin.app.workspace.on('file-open', async () => {
      await sleep(200);
      await tryDecrypt();
    })
  );

  // Strategy 2: active-leaf-change
  plugin.registerEvent(
    plugin.app.workspace.on('active-leaf-change', async () => {
      await sleep(200);
      await tryDecrypt();
    })
  );

  // Strategy 3: on layout ready (for files already open at plugin load)
  plugin.app.workspace.onLayoutReady(async () => {
    await sleep(500);
    await tryDecrypt();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
