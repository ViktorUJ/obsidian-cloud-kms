/**
 * Inline block encryption/decryption hooks.
 *
 * Save hook: Finds all ```secret blocks in non-.secret.md files,
 * encrypts their content, and replaces them with ```ocke-v1 blocks.
 *
 * Open hook: When autoDecryptBlocks is enabled, finds all ```ocke-v1 blocks
 * in the editor, decrypts them, and replaces with ```secret blocks.
 *
 * Each ```secret block gets its own independent DEK (envelope encryption).
 * Processing flags prevent re-trigger loops when the hook writes back.
 */

import type { Plugin, TAbstractFile, TFile } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';
import { encodeInlineBlock, decodeInlineBlock } from '../format/inline-codec';
import { serialize } from '../format/serializer';
import { parse } from '../format/parser';
import { atomicFileWrite } from '../utils/atomic-write';
import { FORMAT_VERSION } from '../constants';
import { showErrorNotice, showNotice } from '../ui/notices';
import { PluginError } from '../providers/errors';
import { MarkdownView } from 'obsidian';

/**
 * Regex to find ```secret blocks.
 * Matches: ```secret\n<content>\n```
 * Uses non-greedy match for content.
 */
const SECRET_BLOCK_REGEX = /```secret\n([\s\S]*?)\n```/g;

/**
 * Regex to find ```ocke-v1 blocks.
 * Matches: ```ocke-v1\n<content>\n```
 * Uses non-greedy match for content.
 */
const ENCRYPTED_BLOCK_REGEX = /```ocke-v1\n([\s\S]*?)\n```/g;

/**
 * Set of file paths currently being processed by the inline block save hook.
 * Prevents re-entrant processing when the atomic write triggers another modify event.
 */
const processingPaths = new Set<string>();

/**
 * Register the inline block save hook that encrypts ```secret blocks on save.
 *
 * On vault modify event:
 * - Skips files matching the encrypted suffix (.secret.md)
 * - Finds all ```secret blocks
 * - Encrypts each block's content independently
 * - Replaces with ```ocke-v1 blocks
 * - Writes back atomically
 *
 * @param plugin - The Obsidian plugin instance
 * @param cryptoEngine - The CryptoEngine for envelope encryption
 * @param getSettings - Accessor for current plugin settings
 */
export function registerInlineBlockSaveHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.vault.on('modify', (file: TAbstractFile) => {
      // Only process files (not folders)
      if (!isFile(file)) {
        return;
      }

      const settings = getSettings();

      // Skip files that match the encrypted suffix — those are handled by the full-file save hook
      if (matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
        return;
      }

      // Prevent re-entrant processing
      if (processingPaths.has(file.path)) {
        return;
      }

      // Fire-and-forget the async encryption
      handleInlineBlockEncryption(file, plugin, cryptoEngine, settings).catch(
        () => {
          // Errors are handled inside handleInlineBlockEncryption
        }
      );
    })
  );
}

/**
 * Register the inline block open hook that decrypts ```ocke-v1 blocks on file open.
 *
 * On file-open event:
 * - If autoDecryptBlocks is false, returns (no-op)
 * - Reads editor content
 * - Finds all ```ocke-v1 blocks
 * - Decrypts each block independently
 * - Replaces with ```secret blocks in the editor
 * - On single block failure: leaves that block as ```ocke-v1 (graceful degradation)
 *
 * @param plugin - The Obsidian plugin instance
 * @param cryptoEngine - The CryptoEngine for decryption
 * @param getSettings - Accessor for current plugin settings
 */
export function registerInlineBlockOpenHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.workspace.on('file-open', async (file: TFile | null) => {
      if (!file) return;

      const settings = getSettings();

      // If auto-decrypt is disabled, do nothing
      if (!settings.autoDecryptBlocks) {
        return;
      }

      // Skip files that match the encrypted suffix — those are handled by the full-file open hook
      if (matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) {
        return;
      }

      try {
        await handleInlineBlockDecryption(plugin, file, cryptoEngine);
      } catch {
        // Top-level errors are swallowed for graceful degradation
      }
    })
  );
}

/**
 * Handle encryption of all ```secret blocks in a file.
 */
async function handleInlineBlockEncryption(
  file: TFile,
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  settings: PluginSettings
): Promise<void> {
  processingPaths.add(file.path);

  try {
    // Read file content
    const content = await plugin.app.vault.read(file);

    // Check if there are any ```secret blocks
    SECRET_BLOCK_REGEX.lastIndex = 0;
    if (!SECRET_BLOCK_REGEX.test(content)) {
      return;
    }

    // Validate that a CMK ARN is configured
    if (!settings.awsCmkArn || settings.awsCmkArn.trim() === '') {
      showNotice(`Cannot encrypt inline blocks in "${file.path}": no CMK ARN configured`);
      return;
    }

    // Reset regex for actual processing
    SECRET_BLOCK_REGEX.lastIndex = 0;

    let result = content;
    let match: RegExpExecArray | null;
    const replacements: Array<{ original: string; encrypted: string }> = [];

    // Collect all matches first (to avoid issues with modifying string during iteration)
    const matches: Array<{ fullMatch: string; content: string }> = [];
    while ((match = SECRET_BLOCK_REGEX.exec(content)) !== null) {
      matches.push({ fullMatch: match[0], content: match[1] });
    }

    // Encrypt each block independently
    for (const m of matches) {
      const plaintext = m.content;
      const encoder = new TextEncoder();
      const plaintextBytes = encoder.encode(plaintext);

      // Build encryption context
      const context: EncryptionContext = {
        vaultName: plugin.app.vault.getName(),
        filePath: file.path,
        formatVersion: FORMAT_VERSION,
      };

      // Encrypt
      const record = await cryptoEngine.encrypt(
        plaintextBytes,
        settings.awsCmkArn,
        'aws-kms',
        context
      );

      // Serialize to binary, then encode as inline block
      const serializedBytes = serialize(record);
      const inlineBlock = encodeInlineBlock(serializedBytes);

      replacements.push({ original: m.fullMatch, encrypted: inlineBlock });
    }

    // Apply all replacements
    for (const r of replacements) {
      result = result.replace(r.original, r.encrypted);
    }

    // Only write if content actually changed
    if (result === content) {
      return;
    }

    // Atomic write
    const encoder = new TextEncoder();
    const newContentBytes = encoder.encode(result);
    await atomicFileWrite(plugin.app.vault, file.path, newContentBytes);
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

/**
 * Handle decryption of all ```ocke-v1 blocks in the editor on file open.
 */
async function handleInlineBlockDecryption(
  plugin: Plugin,
  file: TFile,
  cryptoEngine: CryptoEngine
): Promise<void> {
  const activeView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
  if (!activeView || activeView.file?.path !== file.path) {
    return;
  }

  const content = activeView.editor.getValue();

  // Check if there are any ```ocke-v1 blocks
  ENCRYPTED_BLOCK_REGEX.lastIndex = 0;
  if (!ENCRYPTED_BLOCK_REGEX.test(content)) {
    return;
  }

  // Reset regex for actual processing
  ENCRYPTED_BLOCK_REGEX.lastIndex = 0;

  let result = content;
  let match: RegExpExecArray | null;

  // Collect all matches first
  const matches: Array<{ fullMatch: string; base64Content: string }> = [];
  while ((match = ENCRYPTED_BLOCK_REGEX.exec(content)) !== null) {
    matches.push({ fullMatch: match[0], base64Content: match[1] });
  }

  // Decrypt each block independently — on failure, leave that block unchanged
  for (const m of matches) {
    try {
      // Decode the inline block (base64 → binary)
      const binaryData = decodeInlineBlock(m.fullMatch);
      if (!binaryData) {
        continue; // Skip malformed blocks
      }

      // Parse the binary data into an EncryptedFileRecord
      const record = parse(binaryData);

      // Build encryption context
      const context: EncryptionContext = {
        vaultName: plugin.app.vault.getName(),
        filePath: file.path,
        formatVersion: FORMAT_VERSION,
      };

      // Decrypt
      const plaintextBytes = await cryptoEngine.decrypt(record, context);
      const plaintext = new TextDecoder().decode(plaintextBytes);

      // Replace the encrypted block with a secret block
      const secretBlock = '```secret\n' + plaintext + '\n```';
      result = result.replace(m.fullMatch, secretBlock);
    } catch {
      // Graceful degradation: leave this block as ```ocke-v1
      continue;
    }
  }

  // Only update editor if content changed
  if (result !== content) {
    activeView.editor.setValue(result);
  }
}

/**
 * Type guard to check if a TAbstractFile is a TFile.
 */
function isFile(file: TAbstractFile): file is TFile {
  return 'extension' in file;
}
