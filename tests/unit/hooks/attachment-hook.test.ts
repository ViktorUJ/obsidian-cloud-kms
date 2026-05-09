/**
 * Unit tests for the encrypted attachment hook.
 *
 * Tests cover:
 * - File size limit enforcement (50 MB)
 * - Decryption flow (parse → decrypt → Blob URL)
 * - Blob URL lifecycle (create, reuse, revoke on view close)
 * - Reference counting and cleanup timer
 * - Error handling (KMS failure, integrity failure, size limit)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  AttachmentBlobRegistry,
  AttachmentBlobEntry,
  decryptAttachmentBytes,
  createBlobUrl,
  addViewReference,
  removeViewReference,
  cleanupBlobEntry,
  handleAttachmentRequest,
  registerAttachmentHook,
  getMimeType,
  isEncryptedAttachment,
} from '../../../src/hooks/attachment-hook';
import { BufferRegistry } from '../../../src/core/buffer-registry';
import { PluginError } from '../../../src/providers/errors';
import { MAX_ATTACHMENT_SIZE } from '../../../src/constants';
import { serialize } from '../../../src/format/serializer';
import { MAGIC_BYTES, FORMAT_VERSION } from '../../../src/constants';
import type { CryptoEngine, EncryptedFileRecord, EncryptionContext, PluginSettings } from '../../../src/types';

// Mock URL.createObjectURL and URL.revokeObjectURL
const mockCreateObjectURL = vi.fn().mockReturnValue('blob:mock-url-123');
const mockRevokeObjectURL = vi.fn();
globalThis.URL.createObjectURL = mockCreateObjectURL;
globalThis.URL.revokeObjectURL = mockRevokeObjectURL;

// Mock Blob
globalThis.Blob = class MockBlob {
  parts: any[];
  options: any;
  constructor(parts: any[], options?: any) {
    this.parts = parts;
    this.options = options;
  }
} as any;

describe('attachment-hook', () => {
  let bufferRegistry: BufferRegistry;

  beforeEach(() => {
    bufferRegistry = new BufferRegistry();
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('isEncryptedAttachment', () => {
    it('should match .enc.png extension', () => {
      expect(isEncryptedAttachment('screenshot.enc.png')).toBe(true);
    });

    it('should match .enc.jpg extension', () => {
      expect(isEncryptedAttachment('photo.enc.jpg')).toBe(true);
    });

    it('should match .enc.pdf extension', () => {
      expect(isEncryptedAttachment('document.enc.pdf')).toBe(true);
    });

    it('should match case-insensitively', () => {
      expect(isEncryptedAttachment('photo.ENC.JPG')).toBe(true);
      expect(isEncryptedAttachment('doc.Enc.Pdf')).toBe(true);
    });

    it('should not match regular files', () => {
      expect(isEncryptedAttachment('photo.png')).toBe(false);
      expect(isEncryptedAttachment('notes.secret.md')).toBe(false);
      expect(isEncryptedAttachment('file.enc')).toBe(false);
    });

    it('should not match empty string', () => {
      expect(isEncryptedAttachment('')).toBe(false);
    });
  });

  describe('getMimeType', () => {
    it('should return image/png for .enc.png', () => {
      expect(getMimeType('file.enc.png')).toBe('image/png');
    });

    it('should return image/jpeg for .enc.jpg', () => {
      expect(getMimeType('file.enc.jpg')).toBe('image/jpeg');
    });

    it('should return application/pdf for .enc.pdf', () => {
      expect(getMimeType('file.enc.pdf')).toBe('application/pdf');
    });

    it('should return application/octet-stream for unknown', () => {
      expect(getMimeType('file.enc.xyz')).toBe('application/octet-stream');
    });
  });

  describe('decryptAttachmentBytes', () => {
    it('should reject files exceeding 50 MB', async () => {
      const largeFile = new Uint8Array(MAX_ATTACHMENT_SIZE + 1);
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn(),
      };

      await expect(
        decryptAttachmentBytes(largeFile, 'large.enc.png', 'test-vault', mockEngine)
      ).rejects.toThrow(PluginError);

      await expect(
        decryptAttachmentBytes(largeFile, 'large.enc.png', 'test-vault', mockEngine)
      ).rejects.toMatchObject({ category: 'size-limit' });
    });

    it('should reject files with invalid format', async () => {
      const invalidFile = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn(),
      };

      await expect(
        decryptAttachmentBytes(invalidFile, 'bad.enc.png', 'test-vault', mockEngine)
      ).rejects.toThrow(PluginError);
    });

    it('should decrypt valid encrypted attachment', async () => {
      const expectedPlaintext = new Uint8Array([1, 2, 3, 4, 5]);
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn().mockResolvedValue(expectedPlaintext),
      };

      // Create a valid encrypted file record and serialize it
      const record: EncryptedFileRecord = {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        wrappedDek: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
        authTag: new Uint8Array(16).fill(0xCC),
        ciphertext: new Uint8Array(64).fill(0xDD),
      };
      const fileBytes = serialize(record);

      const result = await decryptAttachmentBytes(
        fileBytes,
        'photo.enc.png',
        'test-vault',
        mockEngine
      );

      expect(result).toBe(expectedPlaintext);
      expect(mockEngine.decrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: 'aws-kms',
          cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        }),
        expect.objectContaining({
          vaultName: 'test-vault',
          filePath: 'photo.enc.png',
          formatVersion: FORMAT_VERSION,
        })
      );
    });

    it('should propagate decryption errors', async () => {
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn().mockRejectedValue(
          new PluginError('Auth tag mismatch', 'integrity')
        ),
      };

      const record: EncryptedFileRecord = {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        wrappedDek: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
        authTag: new Uint8Array(16).fill(0xCC),
        ciphertext: new Uint8Array(64).fill(0xDD),
      };
      const fileBytes = serialize(record);

      await expect(
        decryptAttachmentBytes(fileBytes, 'photo.enc.png', 'test-vault', mockEngine)
      ).rejects.toMatchObject({ category: 'integrity' });
    });
  });

  describe('createBlobUrl', () => {
    it('should create a Blob URL with correct MIME type', () => {
      const plaintext = new Uint8Array([1, 2, 3]);
      const url = createBlobUrl(plaintext, 'photo.enc.png');

      expect(url).toBe('blob:mock-url-123');
      expect(mockCreateObjectURL).toHaveBeenCalledWith(expect.any(Object));
    });
  });

  describe('AttachmentBlobRegistry', () => {
    it('should track entries by file path', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 1,
        cleanupTimer: null,
      };

      registry.set('photo.enc.png', entry);
      expect(registry.has('photo.enc.png')).toBe(true);
      expect(registry.get('photo.enc.png')).toBe(entry);
      expect(registry.size).toBe(1);
    });

    it('should delete entries', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 1,
        cleanupTimer: null,
      };

      registry.set('photo.enc.png', entry);
      registry.delete('photo.enc.png');
      expect(registry.has('photo.enc.png')).toBe(false);
      expect(registry.size).toBe(0);
    });

    it('should revoke all Blob URLs and zero buffers on revokeAll', () => {
      const registry = new AttachmentBlobRegistry();
      const buffer1 = new Uint8Array([1, 2, 3, 4, 5]);
      const buffer2 = new Uint8Array([6, 7, 8, 9, 10]);

      registry.set('a.enc.png', {
        blobUrl: 'blob:url-1',
        buffer: buffer1,
        refCount: 1,
        cleanupTimer: null,
      });
      registry.set('b.enc.jpg', {
        blobUrl: 'blob:url-2',
        buffer: buffer2,
        refCount: 0,
        cleanupTimer: null,
      });

      registry.revokeAll();

      expect(mockRevokeObjectURL).toHaveBeenCalledWith('blob:url-1');
      expect(mockRevokeObjectURL).toHaveBeenCalledWith('blob:url-2');
      expect(buffer1.every(b => b === 0)).toBe(true);
      expect(buffer2.every(b => b === 0)).toBe(true);
      expect(registry.size).toBe(0);
    });

    it('should clear pending timers on revokeAll', () => {
      const registry = new AttachmentBlobRegistry();
      const timer = setTimeout(() => {}, 5000);

      registry.set('a.enc.png', {
        blobUrl: 'blob:url-1',
        buffer: new Uint8Array(5),
        refCount: 0,
        cleanupTimer: timer,
      });

      registry.revokeAll();
      expect(registry.size).toBe(0);
    });
  });

  describe('addViewReference', () => {
    it('should increment refCount', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 1,
        cleanupTimer: null,
      };
      registry.set('photo.enc.png', entry);

      addViewReference(registry, 'photo.enc.png');
      expect(entry.refCount).toBe(2);
    });

    it('should cancel pending cleanup timer', () => {
      const registry = new AttachmentBlobRegistry();
      const timer = setTimeout(() => {}, 5000);
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 0,
        cleanupTimer: timer,
      };
      registry.set('photo.enc.png', entry);

      addViewReference(registry, 'photo.enc.png');
      expect(entry.cleanupTimer).toBeNull();
      expect(entry.refCount).toBe(1);
    });

    it('should do nothing for unknown file path', () => {
      const registry = new AttachmentBlobRegistry();
      // Should not throw
      addViewReference(registry, 'unknown.enc.png');
    });
  });

  describe('removeViewReference', () => {
    it('should decrement refCount', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 2,
        cleanupTimer: null,
      };
      registry.set('photo.enc.png', entry);

      removeViewReference(registry, 'photo.enc.png', bufferRegistry);
      expect(entry.refCount).toBe(1);
      expect(entry.cleanupTimer).toBeNull();
    });

    it('should schedule cleanup when refCount reaches zero', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 1,
        cleanupTimer: null,
      };
      registry.set('photo.enc.png', entry);

      removeViewReference(registry, 'photo.enc.png', bufferRegistry);
      expect(entry.refCount).toBe(0);
      expect(entry.cleanupTimer).not.toBeNull();
    });

    it('should revoke Blob URL after 5s delay when refCount is zero', () => {
      const registry = new AttachmentBlobRegistry();
      const buffer = new Uint8Array([1, 2, 3, 4, 5]);
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test-revoke',
        buffer,
        refCount: 1,
        cleanupTimer: null,
      };
      registry.set('photo.enc.png', entry);

      removeViewReference(registry, 'photo.enc.png', bufferRegistry);

      // Not yet revoked
      expect(mockRevokeObjectURL).not.toHaveBeenCalled();
      expect(registry.has('photo.enc.png')).toBe(true);

      // Advance time by 5 seconds
      vi.advanceTimersByTime(5000);

      // Now revoked and cleaned up
      expect(mockRevokeObjectURL).toHaveBeenCalledWith('blob:test-revoke');
      expect(buffer.every(b => b === 0)).toBe(true);
      expect(registry.has('photo.enc.png')).toBe(false);
    });

    it('should not go below zero refCount', () => {
      const registry = new AttachmentBlobRegistry();
      const entry: AttachmentBlobEntry = {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(10),
        refCount: 0,
        cleanupTimer: null,
      };
      registry.set('photo.enc.png', entry);

      removeViewReference(registry, 'photo.enc.png', bufferRegistry);
      expect(entry.refCount).toBe(0);
    });

    it('should do nothing for unknown file path', () => {
      const registry = new AttachmentBlobRegistry();
      // Should not throw
      removeViewReference(registry, 'unknown.enc.png', bufferRegistry);
    });
  });

  describe('cleanupBlobEntry', () => {
    it('should revoke Blob URL and zero buffer', () => {
      const registry = new AttachmentBlobRegistry();
      const buffer = new Uint8Array([10, 20, 30, 40, 50]);
      registry.set('photo.enc.png', {
        blobUrl: 'blob:cleanup-test',
        buffer,
        refCount: 0,
        cleanupTimer: null,
      });

      cleanupBlobEntry(registry, 'photo.enc.png');

      expect(mockRevokeObjectURL).toHaveBeenCalledWith('blob:cleanup-test');
      expect(buffer.every(b => b === 0)).toBe(true);
      expect(registry.has('photo.enc.png')).toBe(false);
    });

    it('should cancel pending timer before cleanup', () => {
      const registry = new AttachmentBlobRegistry();
      const timer = setTimeout(() => {}, 5000);
      registry.set('photo.enc.png', {
        blobUrl: 'blob:test',
        buffer: new Uint8Array(5),
        refCount: 0,
        cleanupTimer: timer,
      });

      cleanupBlobEntry(registry, 'photo.enc.png');
      expect(registry.has('photo.enc.png')).toBe(false);
    });

    it('should do nothing for unknown file path', () => {
      const registry = new AttachmentBlobRegistry();
      // Should not throw
      cleanupBlobEntry(registry, 'unknown.enc.png');
    });
  });

  describe('handleAttachmentRequest', () => {
    let mockPlugin: any;
    let mockCryptoEngine: CryptoEngine;
    let blobRegistry: AttachmentBlobRegistry;
    let mockSettings: PluginSettings;

    beforeEach(() => {
      mockPlugin = {
        app: {
          vault: {
            getName: () => 'test-vault',
            readBinary: vi.fn(),
          },
        },
        register: vi.fn(),
        registerExtensions: vi.fn(),
      };

      mockCryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
      };

      blobRegistry = new AttachmentBlobRegistry();

      mockSettings = {
        awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test',
        encryptedNoteSuffix: '.secret.md',
        providers: [],
        vaultPolicies: [],
      };
    });

    it('should reuse existing Blob URL if already decrypted', async () => {
      const existingEntry: AttachmentBlobEntry = {
        blobUrl: 'blob:existing-url',
        buffer: new Uint8Array(5),
        refCount: 1,
        cleanupTimer: null,
      };
      blobRegistry.set('photo.enc.png', existingEntry);

      const file = { path: 'photo.enc.png', stat: { size: 1000 } } as any;
      const result = await handleAttachmentRequest(
        file,
        mockPlugin,
        mockCryptoEngine,
        () => mockSettings,
        blobRegistry,
        bufferRegistry
      );

      expect(result).toBe('blob:existing-url');
      expect(existingEntry.refCount).toBe(2);
      expect(mockPlugin.app.vault.readBinary).not.toHaveBeenCalled();
    });

    it('should reject files exceeding 50 MB via stat', async () => {
      const file = {
        path: 'large.enc.png',
        stat: { size: MAX_ATTACHMENT_SIZE + 1 },
      } as any;

      const result = await handleAttachmentRequest(
        file,
        mockPlugin,
        mockCryptoEngine,
        () => mockSettings,
        blobRegistry,
        bufferRegistry
      );

      expect(result).toBeNull();
      expect(mockPlugin.app.vault.readBinary).not.toHaveBeenCalled();
    });

    it('should decrypt and create Blob URL for valid attachment', async () => {
      // Create a valid encrypted file
      const record: EncryptedFileRecord = {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        wrappedDek: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
        authTag: new Uint8Array(16).fill(0xCC),
        ciphertext: new Uint8Array(64).fill(0xDD),
      };
      const fileBytes = serialize(record);

      mockPlugin.app.vault.readBinary.mockResolvedValue(fileBytes.buffer);
      const decryptedBytes = new Uint8Array([0xFF, 0xFE, 0xFD]);
      mockCryptoEngine.decrypt = vi.fn().mockResolvedValue(decryptedBytes);

      const file = { path: 'photo.enc.png', stat: { size: fileBytes.length } } as any;
      const result = await handleAttachmentRequest(
        file,
        mockPlugin,
        mockCryptoEngine,
        () => mockSettings,
        blobRegistry,
        bufferRegistry
      );

      expect(result).toBe('blob:mock-url-123');
      expect(blobRegistry.has('photo.enc.png')).toBe(true);
      const entry = blobRegistry.get('photo.enc.png')!;
      expect(entry.refCount).toBe(1);
      expect(entry.blobUrl).toBe('blob:mock-url-123');
    });

    it('should return null and show notice on decryption failure', async () => {
      const record: EncryptedFileRecord = {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        wrappedDek: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
        authTag: new Uint8Array(16).fill(0xCC),
        ciphertext: new Uint8Array(64).fill(0xDD),
      };
      const fileBytes = serialize(record);

      mockPlugin.app.vault.readBinary.mockResolvedValue(fileBytes.buffer);
      mockCryptoEngine.decrypt = vi.fn().mockRejectedValue(
        new PluginError('KMS timeout', 'timeout')
      );

      const file = { path: 'photo.enc.png', stat: { size: fileBytes.length } } as any;
      const result = await handleAttachmentRequest(
        file,
        mockPlugin,
        mockCryptoEngine,
        () => mockSettings,
        blobRegistry,
        bufferRegistry
      );

      expect(result).toBeNull();
      expect(blobRegistry.has('photo.enc.png')).toBe(false);
    });
  });

  describe('registerAttachmentHook', () => {
    it('should register extensions and return a blob registry', () => {
      const mockPlugin: any = {
        registerExtensions: vi.fn(),
        register: vi.fn(),
      };
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn(),
      };

      const registry = registerAttachmentHook(
        mockPlugin,
        mockEngine,
        () => ({
          awsCmkArn: '',
          encryptedNoteSuffix: '.secret.md',
          providers: [],
          vaultPolicies: [],
        }),
        bufferRegistry
      );

      expect(registry).toBeInstanceOf(AttachmentBlobRegistry);
      expect(mockPlugin.registerExtensions).toHaveBeenCalledWith(
        ['enc.png', 'enc.jpg', 'enc.pdf'],
        'markdown'
      );
      expect(mockPlugin.register).toHaveBeenCalled();
    });

    it('should register cleanup callback that revokes all on unload', () => {
      const mockPlugin: any = {
        registerExtensions: vi.fn(),
        register: vi.fn(),
      };
      const mockEngine: CryptoEngine = {
        encrypt: vi.fn(),
        decrypt: vi.fn(),
      };

      const registry = registerAttachmentHook(
        mockPlugin,
        mockEngine,
        () => ({
          awsCmkArn: '',
          encryptedNoteSuffix: '.secret.md',
          providers: [],
          vaultPolicies: [],
        }),
        bufferRegistry
      );

      // Add an entry to the registry
      registry.set('test.enc.png', {
        blobUrl: 'blob:test-cleanup',
        buffer: new Uint8Array([1, 2, 3]),
        refCount: 1,
        cleanupTimer: null,
      });

      // Simulate plugin unload by calling the registered cleanup function
      const cleanupFn = mockPlugin.register.mock.calls[0][0];
      cleanupFn();

      expect(mockRevokeObjectURL).toHaveBeenCalledWith('blob:test-cleanup');
      expect(registry.size).toBe(0);
    });
  });
});
