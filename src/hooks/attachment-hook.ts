/**
 * Encrypted Attachment Hook — handles decryption and Blob URL lifecycle
 * for encrypted attachments (.enc.png, .enc.jpg, .enc.pdf).
 *
 * Flow:
 *   1. Register handling for encrypted attachment extensions
 *   2. On request: check size ≤ 50 MB → read → parse → decrypt → Blob URL
 *   3. Track Blob URL per file path with reference counting per view
 *   4. On view close: decrement ref count → if zero, revoke Blob URL + release buffer (within 5s)
 *
 * Security:
 *   - Never writes decrypted bytes to disk
 *   - Blob URL revoked and buffer released when no views reference it
 *   - Buffer tracked in BufferRegistry for force-release on plugin unload
 */

import { Notice, Plugin, TFile } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import type { BufferRegistry } from '../core/buffer-registry';
import { parse } from '../format/parser';
import { MAX_ATTACHMENT_SIZE, NOTICE_DURATION_MS } from '../constants';
import { PluginError } from '../providers/errors';

/**
 * Tracked state for a single decrypted attachment Blob URL.
 */
export interface AttachmentBlobEntry {
  /** The Blob URL created from decrypted bytes */
  blobUrl: string;
  /** The decrypted plaintext buffer (held in memory) */
  buffer: Uint8Array;
  /** Number of views currently referencing this Blob URL */
  refCount: number;
  /** Timeout handle for delayed cleanup (5s after last view closes) */
  cleanupTimer: number | null;
}

/** Delay before revoking Blob URL after last view closes (ms) */
const BLOB_CLEANUP_DELAY_MS = 5000;

/** Supported encrypted attachment extensions */
const ENCRYPTED_ATTACHMENT_EXTENSIONS = ['enc.png', 'enc.jpg', 'enc.pdf'];

/**
 * Registry tracking active Blob URLs for encrypted attachments.
 * Maps vault-relative file path → AttachmentBlobEntry.
 */
export class AttachmentBlobRegistry {
  private readonly _entries: Map<string, AttachmentBlobEntry> = new Map();

  get(filePath: string): AttachmentBlobEntry | undefined {
    return this._entries.get(filePath);
  }

  set(filePath: string, entry: AttachmentBlobEntry): void {
    this._entries.set(filePath, entry);
  }

  delete(filePath: string): void {
    this._entries.delete(filePath);
  }

  has(filePath: string): boolean {
    return this._entries.has(filePath);
  }

  /** Get all tracked file paths (for testing/debugging) */
  get size(): number {
    return this._entries.size;
  }

  /**
   * Revoke all Blob URLs and clear all entries.
   * Called on plugin unload.
   */
  revokeAll(): void {
    for (const [, entry] of this._entries) {
      if (entry.cleanupTimer !== null) {
        window.clearTimeout(entry.cleanupTimer);
      }
      try {
        URL.revokeObjectURL(entry.blobUrl);
      } catch {
        // Ignore errors during cleanup
      }
      // Zero the buffer
      entry.buffer.fill(0);
    }
    this._entries.clear();
  }
}

/**
 * Determine the MIME type for an encrypted attachment based on its extension.
 */
export function getMimeType(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.enc.png')) return 'image/png';
  if (lower.endsWith('.enc.jpg')) return 'image/jpeg';
  if (lower.endsWith('.enc.pdf')) return 'application/pdf';
  return 'application/octet-stream';
}

/**
 * Check if a file path matches an encrypted attachment extension.
 */
export function isEncryptedAttachment(filePath: string): boolean {
  if (!filePath) return false;
  const lower = filePath.toLowerCase();
  return ENCRYPTED_ATTACHMENT_EXTENSIONS.some(ext => lower.endsWith(`.${ext}`));
}

/**
 * Decrypt an encrypted attachment file and return the plaintext bytes.
 *
 * @param fileBytes - The raw encrypted file bytes from disk
 * @param filePath - Vault-relative file path (for encryption context)
 * @param vaultName - Name of the vault (for encryption context)
 * @param cryptoEngine - CryptoEngine instance for decryption
 * @returns The decrypted plaintext bytes
 * @throws PluginError on size limit, parse, or decryption failure
 */
export async function decryptAttachmentBytes(
  fileBytes: Uint8Array,
  filePath: string,
  vaultName: string,
  cryptoEngine: CryptoEngine
): Promise<Uint8Array> {
  // 1. Check file size ≤ MAX_ATTACHMENT_SIZE (50 MB)
  if (fileBytes.byteLength > MAX_ATTACHMENT_SIZE) {
    throw new PluginError(
      `Attachment exceeds 50 MB size limit: ${filePath} (${(fileBytes.byteLength / 1024 / 1024).toFixed(1)} MB)`,
      'size-limit',
      undefined,
      undefined,
      filePath
    );
  }

  // 2. Parse → EncryptedFileRecord
  const record = parse(fileBytes);

  // 3. Build EncryptionContext
  const context: EncryptionContext = {
    vaultName,
    filePath,
    formatVersion: record.version,
  };

  // 4. Decrypt → plaintext bytes
  const plaintext = await cryptoEngine.decrypt(record, context);

  return plaintext;
}

/**
 * Create a Blob URL from decrypted plaintext bytes.
 *
 * @param plaintext - The decrypted attachment bytes
 * @param filePath - The file path (used to determine MIME type)
 * @returns The created Blob URL string
 */
export function createBlobUrl(plaintext: Uint8Array, filePath: string): string {
  const mimeType = getMimeType(filePath);
  const blob = new Blob([plaintext], { type: mimeType });
  return URL.createObjectURL(blob);
}

/**
 * Register a view reference for an attachment Blob URL.
 * Increments the reference count and cancels any pending cleanup timer.
 *
 * @param registry - The AttachmentBlobRegistry
 * @param filePath - Vault-relative file path
 */
export function addViewReference(
  registry: AttachmentBlobRegistry,
  filePath: string
): void {
  const entry = registry.get(filePath);
  if (!entry) return;

  entry.refCount++;

  // Cancel any pending cleanup since a new view is referencing this
  if (entry.cleanupTimer !== null) {
    window.clearTimeout(entry.cleanupTimer);
    entry.cleanupTimer = null;
  }
}

/**
 * Remove a view reference for an attachment Blob URL.
 * Decrements the reference count. If zero, schedules cleanup after 5s delay.
 *
 * @param registry - The AttachmentBlobRegistry
 * @param filePath - Vault-relative file path
 * @param bufferRegistry - BufferRegistry for buffer lifecycle tracking
 */
export function removeViewReference(
  registry: AttachmentBlobRegistry,
  filePath: string,
  _bufferRegistry: BufferRegistry
): void {
  const entry = registry.get(filePath);
  if (!entry) return;

  entry.refCount = Math.max(0, entry.refCount - 1);

  if (entry.refCount === 0) {
    // Schedule cleanup after delay
    entry.cleanupTimer = window.setTimeout(() => {
      cleanupBlobEntry(registry, filePath);
    }, BLOB_CLEANUP_DELAY_MS);
  }
}

/**
 * Immediately revoke a Blob URL and release its buffer.
 *
 * @param registry - The AttachmentBlobRegistry
 * @param filePath - Vault-relative file path to clean up
 */
export function cleanupBlobEntry(
  registry: AttachmentBlobRegistry,
  filePath: string
): void {
  const entry = registry.get(filePath);
  if (!entry) return;

  // Cancel any pending timer
  if (entry.cleanupTimer !== null) {
    window.clearTimeout(entry.cleanupTimer);
    entry.cleanupTimer = null;
  }

  // Revoke the Blob URL
  try {
    URL.revokeObjectURL(entry.blobUrl);
  } catch {
    // Ignore errors during revocation
  }

  // Zero-fill and release the buffer
  entry.buffer.fill(0);

  // Remove from registry
  registry.delete(filePath);
}

/**
 * Handle an attachment request: decrypt, create Blob URL, track lifecycle.
 *
 * @param file - The Obsidian TFile for the encrypted attachment
 * @param plugin - The Obsidian plugin instance (for vault access)
 * @param cryptoEngine - CryptoEngine for decryption
 * @param getSettings - Function to get current plugin settings
 * @param blobRegistry - AttachmentBlobRegistry for Blob URL tracking
 * @param bufferRegistry - BufferRegistry for buffer lifecycle
 * @returns The Blob URL for the decrypted attachment, or null on failure
 */
export async function handleAttachmentRequest(
  file: TFile,
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings,
  blobRegistry: AttachmentBlobRegistry,
  _bufferRegistry: BufferRegistry
): Promise<string | null> {
  const filePath = file.path;

  // If already decrypted and tracked, reuse existing Blob URL
  const existing = blobRegistry.get(filePath);
  if (existing) {
    addViewReference(blobRegistry, filePath);
    return existing.blobUrl;
  }

  try {
    // 1. Check file size from stat
    if (file.stat && file.stat.size > MAX_ATTACHMENT_SIZE) {
      new Notice(
        `Attachment exceeds 50 MB size limit: ${filePath}`,
        NOTICE_DURATION_MS
      );
      return null;
    }

    // 2. Read encrypted file bytes from vault
    const fileBytes = new Uint8Array(
      await (plugin.app.vault as any).readBinary(file)
    );

    // 3. Decrypt
    const vaultName = plugin.app.vault.getName();
    const plaintext = await decryptAttachmentBytes(
      fileBytes,
      filePath,
      vaultName,
      cryptoEngine
    );

    // 4. Create Blob URL
    const blobUrl = createBlobUrl(plaintext, filePath);

    // 5. Track in registry with refCount = 1
    const entry: AttachmentBlobEntry = {
      blobUrl,
      buffer: plaintext,
      refCount: 1,
      cleanupTimer: null,
    };
    blobRegistry.set(filePath, entry);

    return blobUrl;
  } catch (err) {
    // Release any in-memory buffer on failure
    const message = err instanceof PluginError
      ? `Attachment decryption failed (${err.category}): ${filePath}`
      : `Attachment decryption failed: ${filePath}`;

    new Notice(message, NOTICE_DURATION_MS);
    return null;
  }
}

/**
 * Register the attachment hook with the plugin.
 *
 * Sets up:
 * - Extension registration for .enc.png, .enc.jpg, .enc.pdf
 * - Blob URL lifecycle management
 * - Cleanup on plugin unload
 *
 * @param plugin - The Obsidian plugin instance
 * @param cryptoEngine - CryptoEngine for decryption
 * @param getSettings - Function to get current plugin settings
 * @param bufferRegistry - BufferRegistry for buffer lifecycle tracking
 * @returns The AttachmentBlobRegistry for external access (e.g., view close handlers)
 */
export function registerAttachmentHook(
  plugin: Plugin,
  _cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings,
  _bufferRegistry: BufferRegistry
): AttachmentBlobRegistry {
  const blobRegistry = new AttachmentBlobRegistry();

  // Register extensions for encrypted attachments
  try {
    (plugin as any).registerExtensions(
      ENCRYPTED_ATTACHMENT_EXTENSIONS,
      'markdown'
    );
  } catch {
    // Extension registration may fail if already registered; continue
  }

  // Register cleanup on plugin unload
  plugin.register(() => {
    blobRegistry.revokeAll();
  });

  return blobRegistry;
}
