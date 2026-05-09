/**
 * Unit tests for the save hook (transparent encryption on save).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerSaveHook } from '../../../src/hooks/save-hook';
import type { CryptoEngine, EncryptedFileRecord, PluginSettings } from '../../../src/types';
import { MAGIC_BYTES, FORMAT_VERSION } from '../../../src/constants';

// Mock obsidian module
vi.mock('obsidian', () => ({
  Notice: vi.fn(),
}));

/**
 * Helper to create a mock plugin with vault event registration.
 */
function createMockPlugin() {
  const eventHandlers: Array<{ name: string; handler: Function }> = [];
  const vault = {
    getName: () => 'test-vault',
    read: vi.fn(),
    adapter: {
      writeBinary: vi.fn().mockResolvedValue(undefined),
      rename: vi.fn().mockResolvedValue(undefined),
      remove: vi.fn().mockResolvedValue(undefined),
    },
    on: vi.fn((name: string, handler: Function) => {
      eventHandlers.push({ name, handler });
      return { name, handler }; // Return an EventRef-like object
    }),
  };

  const plugin = {
    app: { vault },
    registerEvent: vi.fn((eventRef: any) => {
      // Obsidian's registerEvent just tracks the event for cleanup
    }),
  };

  return { plugin, vault, eventHandlers };
}

/**
 * Helper to create a mock CryptoEngine.
 */
function createMockCryptoEngine(): CryptoEngine {
  return {
    encrypt: vi.fn().mockResolvedValue({
      magic: new Uint8Array(MAGIC_BYTES),
      version: FORMAT_VERSION,
      providerId: 'aws-kms',
      cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
      wrappedDek: new Uint8Array(32).fill(0xAA),
      nonce: new Uint8Array(12).fill(0xBB),
      authTag: new Uint8Array(16).fill(0xCC),
      ciphertext: new Uint8Array([0x01, 0x02, 0x03]),
    } satisfies EncryptedFileRecord),
    decrypt: vi.fn(),
  };
}

/**
 * Helper to create default settings.
 */
function createSettings(overrides?: Partial<PluginSettings>): PluginSettings {
  return {
    awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    encryptedNoteSuffix: '.secret.md',
    providers: [],
    vaultPolicies: [],
    ...overrides,
  };
}

describe('registerSaveHook', () => {
  let mockPlugin: ReturnType<typeof createMockPlugin>['plugin'];
  let mockVault: ReturnType<typeof createMockPlugin>['vault'];
  let eventHandlers: ReturnType<typeof createMockPlugin>['eventHandlers'];
  let mockCryptoEngine: CryptoEngine;
  let settings: PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    const mocks = createMockPlugin();
    mockPlugin = mocks.plugin;
    mockVault = mocks.vault;
    eventHandlers = mocks.eventHandlers;
    mockCryptoEngine = createMockCryptoEngine();
    settings = createSettings();
  });

  it('should register a vault modify event listener', () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    expect(mockVault.on).toHaveBeenCalledWith('modify', expect.any(Function));
    expect(mockPlugin.registerEvent).toHaveBeenCalled();
  });

  it('should encrypt body of a suffix-matching note on save', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/test.secret.md', name: 'test.secret.md', extension: 'md' };

    mockVault.read.mockResolvedValue('Hello, this is plaintext body');

    await handler(file);
    // Allow async processing
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.read).toHaveBeenCalledWith(file);
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
      'aws-kms',
      {
        vaultName: 'test-vault',
        filePath: 'notes/test.secret.md',
        formatVersion: FORMAT_VERSION,
      }
    );
    // Atomic write should have been called (writeBinary + rename)
    expect(mockVault.adapter.writeBinary).toHaveBeenCalled();
    expect(mockVault.adapter.rename).toHaveBeenCalled();
  });

  it('should preserve frontmatter and only encrypt the body', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    const content = '---\ntitle: Secret Note\ntags: [secret]\n---\nThis is the body to encrypt';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    // The encrypt call should receive only the body bytes
    const encoder = new TextEncoder();
    const expectedBody = 'This is the body to encrypt';
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      encoder.encode(expectedBody),
      settings.awsCmkArn,
      'aws-kms',
      expect.any(Object)
    );

    // The written content should start with frontmatter bytes
    const writtenData = mockVault.adapter.writeBinary.mock.calls[0][1] as Uint8Array;
    const frontmatterStr = '---\ntitle: Secret Note\ntags: [secret]\n---\n';
    const frontmatterBytes = encoder.encode(frontmatterStr);

    // Verify frontmatter is preserved at the start
    const writtenFrontmatter = writtenData.slice(0, frontmatterBytes.length);
    expect(writtenFrontmatter).toEqual(frontmatterBytes);
  });

  it('should encrypt entire content when no frontmatter is present', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    mockVault.read.mockResolvedValue('No frontmatter, just body content');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    const encoder = new TextEncoder();
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      encoder.encode('No frontmatter, just body content'),
      settings.awsCmkArn,
      'aws-kms',
      expect.any(Object)
    );
  });

  it('should skip files that do not match the encrypted suffix', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.read).not.toHaveBeenCalled();
    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
  });

  it('should skip already-encrypted body (OCKE magic bytes detected)', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    // Simulate content where body starts with OCKE magic bytes
    // OCKE = 0x4F 0x43 0x4B 0x45 → "OCKE" in ASCII
    const magicStr = String.fromCharCode(0x4F, 0x43, 0x4B, 0x45);
    mockVault.read.mockResolvedValue(magicStr + 'rest of encrypted data');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should skip already-encrypted body after frontmatter', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    // Frontmatter followed by OCKE magic bytes in body
    const magicStr = String.fromCharCode(0x4F, 0x43, 0x4B, 0x45);
    const content = '---\ntitle: Test\n---\n' + magicStr + 'encrypted data';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should abort and show notice when no CMK ARN is configured', async () => {
    settings.awsCmkArn = '';
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    mockVault.read.mockResolvedValue('Some body content');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should leave file unchanged and show notice on encryption failure', async () => {
    const mockEngine: CryptoEngine = {
      encrypt: vi.fn().mockRejectedValue(
        new Error('KMS timeout')
      ),
      decrypt: vi.fn(),
    };

    registerSaveHook(mockPlugin as any, mockEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    mockVault.read.mockResolvedValue('Body to encrypt');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    // Atomic write should NOT have been called
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should not process non-file abstract items (folders)', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    // A folder-like object without 'extension' property
    const folder = { path: 'some-folder', name: 'some-folder' };

    await handler(folder);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.read).not.toHaveBeenCalled();
  });

  it('should use the configured suffix from settings', async () => {
    settings.encryptedNoteSuffix = '.encrypted.md';
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;

    // This file matches the custom suffix
    const matchingFile = { path: 'note.encrypted.md', name: 'note.encrypted.md', extension: 'md' };
    mockVault.read.mockResolvedValue('Body content');

    await handler(matchingFile);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).toHaveBeenCalled();
  });

  it('should skip encryption when body is empty', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    // Frontmatter only, no body
    mockVault.read.mockResolvedValue('---\ntitle: Empty Note\n---\n');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should skip encryption when file content is only frontmatter with no body', async () => {
    registerSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'test.secret.md', name: 'test.secret.md', extension: 'md' };

    // Frontmatter that ends at EOF (no body at all)
    mockVault.read.mockResolvedValue('---\ntitle: Only Frontmatter\n---');

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });
});
