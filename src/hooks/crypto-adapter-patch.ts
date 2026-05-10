/**
 * Monkey-patch vault.adapter to transparently encrypt/decrypt files.
 *
 * It intercepts vault.adapter.read() and vault.adapter.write() to:
 * - On READ: decrypt ````ocke-v1 blocks → ````secret blocks (Obsidian sees plaintext)
 * - On WRITE: encrypt ````secret blocks → ````ocke-v1 blocks (disk has ciphertext)
 *
 * Uses 4 backticks (````) as fence markers so that inner content can contain
 * standard 3-backtick code fences (```mermaid, ```js, etc.) without conflict.
 *
 * This ensures:
 * - The editor always shows decrypted content (````secret)
 * - The disk always has encrypted content (````ocke-v1)
 * - Inner code fences render correctly (mermaid diagrams, code blocks, etc.)
 */

import type { Plugin, DataAdapter } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { decodeInlineBlock, encodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { serialize } from '../format/serializer';
import { FORMAT_VERSION } from '../constants';
import { PluginError } from '../providers/errors';
import { showErrorNotice } from '../ui/notices';

/**
 * Markers for secret blocks.
 * Uses Obsidian comment syntax (%%) which is invisible in Reading view.
 * Content between markers is regular markdown — renders normally (mermaid, code, etc.)
 *
 * Editor shows:   %%secret-start%% ... %%secret-end%%
 * Disk stores:    ````ocke-v1\n<base64>\n````
 */
const SECRET_START = '%%secret-start%%';
const SECRET_END = '%%secret-end%%';
const SECRET_BLOCK_REGEX = /%%secret-start%%\n([\s\S]*?)\n%%secret-end%%/g;
const ENCRYPTED_BLOCK_REGEX = /````ocke-v1\n([\s\S]*?)\n````/g;

/** Tracks paths currently being processed to prevent re-entrancy */
const processing = new Set<string>();

/**
 * Install the crypto adapter patch.
 * Returns a cleanup function to restore original methods on unload.
 */
export function installCryptoAdapterPatch(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): () => void {
  const adapter = plugin.app.vault.adapter;

  // Save original methods
  const originalRead = adapter.read.bind(adapter);
  const originalWrite = adapter.write.bind(adapter);

  /**
   * Patched read: after reading from disk, decrypt ````ocke-v1 → ````secret
   */
  adapter.read = async function (normalizedPath: string): Promise<string> {
    const content = await originalRead(normalizedPath);

    // Skip if no encrypted blocks
    ENCRYPTED_BLOCK_REGEX.lastIndex = 0;
    if (!ENCRYPTED_BLOCK_REGEX.test(content)) {
      return content;
    }

    // Only process .md files
    if (!normalizedPath.endsWith('.md')) {
      return content;
    }

    const settings = getSettings();
    if (!settings.autoDecryptBlocks) {
      return content;
    }

    // Decrypt all ````ocke-v1 blocks → ````secret
    try {
      const decrypted = await decryptBlocks(
        content,
        normalizedPath,
        cryptoEngine,
        plugin.app.vault.getName()
      );
      return decrypted;
    } catch {
      // On failure, return original content (graceful degradation)
      return content;
    }
  };

  /**
   * Patched write: before writing to disk, encrypt ````secret → ````ocke-v1
   */
  adapter.write = async function (normalizedPath: string, data: string, ...args: unknown[]): Promise<void> {
    // Skip if currently processing (prevent re-entrancy)
    if (processing.has(normalizedPath)) {
      return (originalWrite as any)(normalizedPath, data, ...args);
    }

    // Only process .md files
    if (!normalizedPath.endsWith('.md')) {
      return (originalWrite as any)(normalizedPath, data, ...args);
    }

    // Check for ````secret blocks
    SECRET_BLOCK_REGEX.lastIndex = 0;
    if (!SECRET_BLOCK_REGEX.test(data)) {
      return (originalWrite as any)(normalizedPath, data, ...args);
    }

    const settings = getSettings();
    if (!settings.awsCmkArn || settings.awsCmkArn.trim() === '') {
      return (originalWrite as any)(normalizedPath, data, ...args);
    }

    processing.add(normalizedPath);
    try {
      // Encrypt all ````secret blocks → ````ocke-v1
      const encrypted = await encryptBlocks(
        data,
        normalizedPath,
        cryptoEngine,
        settings.awsCmkArn,
        plugin.app.vault.getName()
      );
      return (originalWrite as any)(normalizedPath, encrypted, ...args);
    } catch (err) {
      // On encryption failure, show error but still write original
      // (don't lose user data)
      if (err instanceof PluginError) {
        showErrorNotice(err);
      }
      return (originalWrite as any)(normalizedPath, data, ...args);
    } finally {
      processing.delete(normalizedPath);
    }
  };

  // Return cleanup function
  return () => {
    adapter.read = originalRead;
    adapter.write = originalWrite as any;
  };
}

/**
 * Decrypt all ````ocke-v1 blocks in content → ````secret blocks.
 */
async function decryptBlocks(
  content: string,
  filePath: string,
  cryptoEngine: CryptoEngine,
  vaultName: string
): Promise<string> {
  ENCRYPTED_BLOCK_REGEX.lastIndex = 0;

  const matches: Array<{ fullMatch: string; base64Content: string }> = [];
  let match: RegExpExecArray | null;
  while ((match = ENCRYPTED_BLOCK_REGEX.exec(content)) !== null) {
    matches.push({ fullMatch: match[0], base64Content: match[1] });
  }

  if (matches.length === 0) return content;

  let result = content;

  for (const m of matches) {
    try {
      // Build the 3-backtick format for decodeInlineBlock (it expects ```ocke-v1)
      const fullBlock = '```ocke-v1\n' + m.base64Content + '\n```';
      const binaryData = decodeInlineBlock(fullBlock);
      if (!binaryData) continue;

      const record = parse(binaryData);
      const context: EncryptionContext = {
        vaultName,
        filePath,
        formatVersion: FORMAT_VERSION,
      };

      const plaintextBytes = await cryptoEngine.decrypt(record, context);
      const plaintext = new TextDecoder().decode(plaintextBytes);
      const secretBlock = '%%secret-start%%\n' + plaintext + '\n%%secret-end%%';
      result = result.replace(m.fullMatch, secretBlock);
    } catch {
      // Leave this block as ````ocke-v1 (no key access / decryption failed)
      continue;
    }
  }

  return result;
}

/**
 * Encrypt all ````secret blocks in content → ````ocke-v1 blocks.
 */
async function encryptBlocks(
  content: string,
  filePath: string,
  cryptoEngine: CryptoEngine,
  cmkArn: string,
  vaultName: string
): Promise<string> {
  SECRET_BLOCK_REGEX.lastIndex = 0;

  const matches: Array<{ fullMatch: string; plaintext: string }> = [];
  let match: RegExpExecArray | null;
  while ((match = SECRET_BLOCK_REGEX.exec(content)) !== null) {
    matches.push({ fullMatch: match[0], plaintext: match[1] });
  }

  if (matches.length === 0) return content;

  let result = content;

  for (const m of matches) {
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(m.plaintext);

    const context: EncryptionContext = {
      vaultName,
      filePath,
      formatVersion: FORMAT_VERSION,
    };

    const record = await cryptoEngine.encrypt(
      plaintextBytes,
      cmkArn,
      'aws-kms',
      context
    );

    const serializedBytes = serialize(record);
    const inlineBlock = '````ocke-v1\n' + Buffer.from(serializedBytes).toString('base64') + '\n````';
    result = result.replace(m.fullMatch, inlineBlock);
  }

  return result;
}
