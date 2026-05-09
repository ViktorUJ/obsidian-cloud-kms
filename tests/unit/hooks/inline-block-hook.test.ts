/**
 * Unit tests for the inline block encryption/decryption hooks.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  registerInlineBlockSaveHook,
  registerInlineBlockOpenHook,
} from '../../../src/hooks/inline-block-hook';
import type { CryptoEngine, EncryptedFileRecord, PluginSettings } from '../../../src/types';
import { MAGIC_BYTES, FORMAT_VERSION } from '../../../src/constants';
import { encodeInlineBlock } from '../../../src/format/inline-codec';
import { serialize } from '../../../src/format/serializer';

// Mock obsidian module
vi.mock('obsidian', () => ({
  Notice: vi.fn(),
  MarkdownView: class {
    getViewType() { return 'markdown'; }
  },
}));

/**
 * Helper to create a mock encrypted record for testing.
 */
function createMockRecord(): EncryptedFileRecord {
  return {
    magic: new Uint8Array(MAGIC_BYTES),
    version: FORMAT_VERSION,
    providerId: 'aws-kms',
    cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    wrappedDek: new Uint8Array(32).fill(0xAA),
    nonce: new Uint8Array(12).fill(0xBB),
    authTag: new Uint8Array(16).fill(0xCC),
    ciphertext: new Uint8Array([0x01, 0x02, 0x03]),
  };
}

/**
 * Helper to create a valid ```ocke-v1 block from a record.
 */
function createEncryptedBlock(): string {
  const record = createMockRecord();
  const serialized = serialize(record);
  return encodeInlineBlock(serialized);
}

/**
 * Helper to create a mock plugin for the save hook.
 */
function createMockPluginForSave() {
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
      return { name, handler };
    }),
  };

  const plugin = {
    app: { vault },
    registerEvent: vi.fn(),
  };

  return { plugin, vault, eventHandlers };
}

/**
 * Helper to create a mock plugin for the open hook.
 */
function createMockPluginForOpen(editorContent: string = '') {
  const eventHandlers: Array<{ name: string; handler: Function }> = [];
  const mockEditor = {
    getValue: vi.fn(() => editorContent),
    setValue: vi.fn(),
  };

  const mockActiveView: any = {
    file: null as any,
    editor: mockEditor,
  };

  const workspace = {
    on: vi.fn((name: string, handler: Function) => {
      eventHandlers.push({ name, handler });
      return { name, handler };
    }),
    getActiveViewOfType: vi.fn(() => mockActiveView),
  };

  const vault = {
    getName: () => 'test-vault',
  };

  const plugin = {
    app: { workspace, vault },
    registerEvent: vi.fn(),
    _mockActiveView: mockActiveView,
    _mockEditor: mockEditor,
  };

  return { plugin, eventHandlers };
}

/**
 * Helper to create a mock CryptoEngine.
 */
function createMockCryptoEngine(): CryptoEngine {
  return {
    encrypt: vi.fn().mockResolvedValue(createMockRecord()),
    decrypt: vi.fn().mockResolvedValue(new TextEncoder().encode('decrypted content')),
  };
}

/**
 * Helper to create default settings.
 */
function createSettings(overrides?: Partial<PluginSettings>): PluginSettings {
  return {
    awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    encryptedNoteSuffix: '.secret.md',
    autoDecryptBlocks: true,
    providers: [],
    vaultPolicies: [],
    ...overrides,
  };
}

describe('registerInlineBlockSaveHook', () => {
  let mockPlugin: ReturnType<typeof createMockPluginForSave>['plugin'];
  let mockVault: ReturnType<typeof createMockPluginForSave>['vault'];
  let eventHandlers: ReturnType<typeof createMockPluginForSave>['eventHandlers'];
  let mockCryptoEngine: CryptoEngine;
  let settings: PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    const mocks = createMockPluginForSave();
    mockPlugin = mocks.plugin;
    mockVault = mocks.vault;
    eventHandlers = mocks.eventHandlers;
    mockCryptoEngine = createMockCryptoEngine();
    settings = createSettings();
  });

  it('should register a vault modify event listener', () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    expect(mockVault.on).toHaveBeenCalledWith('modify', expect.any(Function));
    expect(mockPlugin.registerEvent).toHaveBeenCalled();
  });

  it('should encrypt ```secret blocks on save', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    const content = 'Some text\n```secret\nThis is sensitive\n```\nMore text';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      new TextEncoder().encode('This is sensitive'),
      'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
      'aws-kms',
      {
        vaultName: 'test-vault',
        filePath: 'notes/regular.md',
        formatVersion: FORMAT_VERSION,
      }
    );
    // Atomic write should have been called
    expect(mockVault.adapter.writeBinary).toHaveBeenCalled();
    expect(mockVault.adapter.rename).toHaveBeenCalled();
  });

  it('should skip .secret.md files', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/test.secret.md', name: 'test.secret.md', extension: 'md' };

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.read).not.toHaveBeenCalled();
    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
  });

  it('should skip already-encrypted ```ocke-v1 blocks', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    const encryptedBlock = createEncryptedBlock();
    const content = `Some text\n${encryptedBlock}\nMore text`;
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    // No ```secret blocks found, so no encryption should happen
    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should handle multiple ```secret blocks in one file', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/multi.md', name: 'multi.md', extension: 'md' };

    const content = '# Title\n```secret\nFirst secret\n```\nMiddle text\n```secret\nSecond secret\n```\nEnd';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    // Should encrypt both blocks independently
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledTimes(2);
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      new TextEncoder().encode('First secret'),
      expect.any(String),
      'aws-kms',
      expect.any(Object)
    );
    expect(mockCryptoEngine.encrypt).toHaveBeenCalledWith(
      new TextEncoder().encode('Second secret'),
      expect.any(String),
      'aws-kms',
      expect.any(Object)
    );
    expect(mockVault.adapter.writeBinary).toHaveBeenCalled();
  });

  it('should not modify non-secret code blocks', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/code.md', name: 'code.md', extension: 'md' };

    const content = '# Code\n```javascript\nconsole.log("hello");\n```\n```python\nprint("hi")\n```';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should not process non-file abstract items (folders)', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const folder = { path: 'some-folder', name: 'some-folder' };

    await handler(folder);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.read).not.toHaveBeenCalled();
  });

  it('should abort when no CMK ARN is configured', async () => {
    settings.awsCmkArn = '';
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    const content = '```secret\nSensitive data\n```';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockCryptoEngine.encrypt).not.toHaveBeenCalled();
    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should leave file unchanged on encryption failure', async () => {
    const failingEngine: CryptoEngine = {
      encrypt: vi.fn().mockRejectedValue(new Error('KMS timeout')),
      decrypt: vi.fn(),
    };

    registerInlineBlockSaveHook(mockPlugin as any, failingEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    const content = '```secret\nSensitive data\n```';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    expect(mockVault.adapter.writeBinary).not.toHaveBeenCalled();
  });

  it('should write encrypted content that replaces ```secret with ```ocke-v1', async () => {
    registerInlineBlockSaveHook(mockPlugin as any, mockCryptoEngine, () => settings);

    const handler = eventHandlers[0].handler;
    const file = { path: 'notes/regular.md', name: 'regular.md', extension: 'md' };

    const content = 'Before\n```secret\nMy secret\n```\nAfter';
    mockVault.read.mockResolvedValue(content);

    await handler(file);
    await new Promise((r) => setTimeout(r, 10));

    // Verify the written content contains ```ocke-v1 and not ```secret
    const writtenBytes = mockVault.adapter.writeBinary.mock.calls[0][1] as Uint8Array;
    const writtenContent = new TextDecoder().decode(writtenBytes);
    expect(writtenContent).toContain('```ocke-v1\n');
    expect(writtenContent).not.toContain('```secret\n');
    expect(writtenContent).toContain('Before\n');
    expect(writtenContent).toContain('\nAfter');
  });
});

describe('registerInlineBlockOpenHook', () => {
  let settings: PluginSettings;
  let mockCryptoEngine: CryptoEngine;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = createSettings();
    mockCryptoEngine = createMockCryptoEngine();
  });

  it('should register a file-open event handler', () => {
    const { plugin } = createMockPluginForOpen();

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);

    expect(plugin.app.workspace.on).toHaveBeenCalledWith('file-open', expect.any(Function));
    expect(plugin.registerEvent).toHaveBeenCalled();
  });

  it('should decrypt ```ocke-v1 blocks on open when autoDecryptBlocks=true', async () => {
    const encryptedBlock = createEncryptedBlock();
    const editorContent = `Some text\n${encryptedBlock}\nMore text`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/regular.md', name: 'regular.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    expect(mockCryptoEngine.decrypt).toHaveBeenCalled();
    expect(plugin._mockEditor.setValue).toHaveBeenCalled();
    const newContent = plugin._mockEditor.setValue.mock.calls[0][0];
    expect(newContent).toContain('```secret\n');
    expect(newContent).toContain('decrypted content');
    expect(newContent).not.toContain('```ocke-v1\n');
  });

  it('should NOT decrypt on open when autoDecryptBlocks=false', async () => {
    settings.autoDecryptBlocks = false;
    const encryptedBlock = createEncryptedBlock();
    const editorContent = `Some text\n${encryptedBlock}\nMore text`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/regular.md', name: 'regular.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    expect(mockCryptoEngine.decrypt).not.toHaveBeenCalled();
    expect(plugin._mockEditor.setValue).not.toHaveBeenCalled();
  });

  it('should handle multiple encrypted blocks in one file', async () => {
    const encryptedBlock1 = createEncryptedBlock();
    const encryptedBlock2 = createEncryptedBlock();
    const editorContent = `Title\n${encryptedBlock1}\nMiddle\n${encryptedBlock2}\nEnd`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/multi.md', name: 'multi.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    expect(mockCryptoEngine.decrypt).toHaveBeenCalledTimes(2);
    expect(plugin._mockEditor.setValue).toHaveBeenCalled();
    const newContent = plugin._mockEditor.setValue.mock.calls[0][0];
    expect(newContent).toContain('Title\n');
    expect(newContent).toContain('\nMiddle\n');
    expect(newContent).toContain('\nEnd');
  });

  it('should gracefully handle single block decryption failure', async () => {
    let callCount = 0;
    const partialFailEngine: CryptoEngine = {
      encrypt: vi.fn(),
      decrypt: vi.fn(async () => {
        callCount++;
        if (callCount === 1) {
          throw new Error('KMS access denied');
        }
        return new TextEncoder().encode('second decrypted');
      }),
    };

    const encryptedBlock1 = createEncryptedBlock();
    const encryptedBlock2 = createEncryptedBlock();
    const editorContent = `Title\n${encryptedBlock1}\nMiddle\n${encryptedBlock2}\nEnd`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/multi.md', name: 'multi.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, partialFailEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    // Should still set editor value (second block decrypted, first left as-is)
    expect(plugin._mockEditor.setValue).toHaveBeenCalled();
    const newContent = plugin._mockEditor.setValue.mock.calls[0][0];
    // First block should remain encrypted
    expect(newContent).toContain('```ocke-v1\n');
    // Second block should be decrypted
    expect(newContent).toContain('```secret\nsecond decrypted\n```');
  });

  it('should not modify editor when no encrypted blocks are present', async () => {
    const editorContent = '# Regular note\n```javascript\nconsole.log("hi");\n```\nEnd';
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/regular.md', name: 'regular.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    expect(mockCryptoEngine.decrypt).not.toHaveBeenCalled();
    expect(plugin._mockEditor.setValue).not.toHaveBeenCalled();
  });

  it('should ignore null file', async () => {
    const { plugin, eventHandlers } = createMockPluginForOpen();

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(null);

    expect(mockCryptoEngine.decrypt).not.toHaveBeenCalled();
  });

  it('should skip .secret.md files', async () => {
    const encryptedBlock = createEncryptedBlock();
    const editorContent = `Text\n${encryptedBlock}\nEnd`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const file = { path: 'notes/test.secret.md', name: 'test.secret.md' };
    plugin._mockActiveView.file = file;

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(file);

    expect(mockCryptoEngine.decrypt).not.toHaveBeenCalled();
    expect(plugin._mockEditor.setValue).not.toHaveBeenCalled();
  });

  it('should not update editor if active view file does not match opened file', async () => {
    const encryptedBlock = createEncryptedBlock();
    const editorContent = `Text\n${encryptedBlock}\nEnd`;
    const { plugin, eventHandlers } = createMockPluginForOpen(editorContent);
    const openedFile = { path: 'notes/opened.md', name: 'opened.md' };
    // Active view has a different file
    plugin._mockActiveView.file = { path: 'notes/other.md', name: 'other.md' };

    registerInlineBlockOpenHook(plugin as any, mockCryptoEngine, () => settings);
    const handler = eventHandlers[0].handler;

    await handler(openedFile);

    expect(mockCryptoEngine.decrypt).not.toHaveBeenCalled();
    expect(plugin._mockEditor.setValue).not.toHaveBeenCalled();
  });
});
