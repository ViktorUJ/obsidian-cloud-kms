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

import type { Plugin } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { decodeInlineBlock } from '../format/inline-codec';
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
): { uninstall: () => void; originalReadBinary: (path: string) => Promise<ArrayBuffer> } {
  const adapter = plugin.app.vault.adapter;

  // Save original methods
  const originalRead = adapter.read.bind(adapter);
  const originalWrite = adapter.write.bind(adapter);
  const originalReadBinary = adapter.readBinary.bind(adapter);

  /**
   * Patched readBinary: decrypt binary files that start with OCKE magic bytes.
   */
  adapter.readBinary = async function (normalizedPath: string): Promise<ArrayBuffer> {
    const data = await originalReadBinary(normalizedPath);
    const bytes = new Uint8Array(data);

    // Check for OCKE magic bytes (0x4F 0x43 0x4B 0x45)
    if (bytes.length < 4 || bytes[0] !== 0x4F || bytes[1] !== 0x43 || bytes[2] !== 0x4B || bytes[3] !== 0x45) {
      return data;
    }

    // Skip .md files — they use text-based encryption
    if (normalizedPath.endsWith('.md')) {
      return data;
    }

    const settings = getSettings();
    if (!settings.autoDecryptBlocks) {
      return data;
    }

    // Decrypt the binary file
    try {
      const record = parse(bytes);
      const context: EncryptionContext = {
        vaultName: plugin.app.vault.getName(),
        filePath: normalizedPath,
        formatVersion: FORMAT_VERSION,
      };

      const plaintextBytes = await cryptoEngine.decrypt(record, context);
      return plaintextBytes.buffer;
    } catch {
      // On failure, return original (Obsidian won't be able to render it)
      return data;
    }
  };

  /**
   * Blob URL cache for encrypted binary files (lazy, LRU-like).
   * Decryption happens on first access, not at startup.
   */
  const blobUrls = new Map<string, string>();

  /**
   * Patch vault.getResourcePath to return Blob URLs for encrypted binary files.
   */
  const originalGetResourcePath = plugin.app.vault.getResourcePath.bind(plugin.app.vault);
  plugin.app.vault.getResourcePath = function (file: any): string {
    if (!file || !file.path || file.path.endsWith('.md')) {
      return originalGetResourcePath(file);
    }

    const cached = blobUrls.get(file.path);
    if (cached && cached !== '__pending__') {
      return cached;
    }

    if (!cached) {
      triggerBinaryDecrypt(file.path, plugin, cryptoEngine, getSettings, blobUrls, originalReadBinary, originalGetResourcePath);
    }

    return originalGetResourcePath(file);
  };

  /**
   * On file-open: if it's an encrypted binary, wait for decryption
   * then force Obsidian to re-open the file so it picks up the Blob URL.
   */
  plugin.registerEvent(
    plugin.app.workspace.on('file-open', async (file: any) => {
      if (!file || !file.path || file.path.endsWith('.md')) return;

      // Check if already decrypted
      const cached = blobUrls.get(file.path);
      if (cached && cached !== '__pending__') return;

      // Wait for decryption to complete (poll)
      for (let i = 0; i < 50; i++) {
        await new Promise(r => setTimeout(r, 100));
        const url = blobUrls.get(file.path);
        if (url && url !== '__pending__') {
          // Force re-render by triggering a leaf update
          const leaf = plugin.app.workspace.activeLeaf;
          if (leaf) {
            const state = leaf.getViewState();
            await leaf.setViewState({ type: 'empty', state: {} });
            await leaf.setViewState(state);
          }
          return;
        }
      }
    })
  );

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

  // Return cleanup function and original readBinary for decrypt command
  return {
    uninstall: () => {
      adapter.read = originalRead;
      adapter.write = originalWrite as any;
      adapter.readBinary = originalReadBinary;
      plugin.app.vault.getResourcePath = originalGetResourcePath;
      for (const url of blobUrls.values()) {
        try { URL.revokeObjectURL(url); } catch { /* ignore */ }
      }
      blobUrls.clear();
    },
    originalReadBinary,
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

/**
 * Trigger async decryption of a binary file and create a Blob URL.
 * Once decrypted, the Blob URL is stored in the cache.
 * Obsidian will re-request getResourcePath on next render cycle.
 */
async function triggerBinaryDecrypt(
  filePath: string,
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings,
  blobUrls: Map<string, string>,
  originalReadBinary: (path: string) => Promise<ArrayBuffer>,
  _originalGetResourcePath: (file: any) => string
): Promise<void> {
  // Prevent duplicate decryption attempts
  if (blobUrls.has(filePath)) return;
  // Use a sentinel to prevent re-triggering
  blobUrls.set(filePath, '__pending__');

  try {
    const settings = getSettings();
    if (!settings.autoDecryptBlocks) {
      blobUrls.delete(filePath);
      return;
    }

    const data = await originalReadBinary(filePath);
    const bytes = new Uint8Array(data);

    // Verify OCKE magic
    if (bytes.length < 4 || bytes[0] !== 0x4F || bytes[1] !== 0x43 || bytes[2] !== 0x4B || bytes[3] !== 0x45) {
      blobUrls.delete(filePath);
      return;
    }

    const record = parse(bytes);
    const context: EncryptionContext = {
      vaultName: plugin.app.vault.getName(),
      filePath,
      formatVersion: FORMAT_VERSION,
    };

    const plaintextBytes = await cryptoEngine.decrypt(record, context);

    // Determine MIME type from extension
    const mimeType = getMimeTypeFromPath(filePath);
    const blob = new Blob([plaintextBytes], { type: mimeType });
    const blobUrl = URL.createObjectURL(blob);

    blobUrls.set(filePath, blobUrl);

    // Evict old entries if cache exceeds 20
    if (blobUrls.size > 20) {
      let toRemove = blobUrls.size - 20;
      for (const [p, u] of blobUrls) {
        if (toRemove <= 0) break;
        if (u === '__pending__' || p === filePath) continue;
        try { URL.revokeObjectURL(u); } catch { /* ignore */ }
        blobUrls.delete(p);
        toRemove--;
      }
    }

    // Force Obsidian to re-render the file by triggering a metadata change
    const file = plugin.app.vault.getAbstractFileByPath(filePath);
    if (file) {
      plugin.app.metadataCache.trigger('changed', file);
    }
  } catch {
    blobUrls.delete(filePath);
  }
}

/**
 * Get MIME type from file path extension.
 */
function getMimeTypeFromPath(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  const mimeMap: Record<string, string> = {
    pdf: 'application/pdf',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    svg: 'image/svg+xml',
    webp: 'image/webp',
    mp3: 'audio/mpeg',
    mp4: 'video/mp4',
    wav: 'audio/wav',
    ogg: 'audio/ogg',
    webm: 'video/webm',
  };
  return mimeMap[ext] ?? 'application/octet-stream';
}
