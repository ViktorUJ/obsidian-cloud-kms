/**
 * Unit tests for the open hook (transparent decryption on open).
 * Validates: Requirements 5.7, 5.8
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerOpenHook } from '../../../src/hooks/open-hook';
import type { CryptoEngine, EncryptedFileRecord, PluginSettings } from '../../../src/types';
import { MAGIC_BYTES, FORMAT_VERSION, NOTICE_DURATION_MS } from '../../../src/constants';
import { serialize } from '../../../src/format/serializer';
import { PluginError } from '../../../src/providers/errors';

// Track Notice calls
const noticeCalls: Array<{ message: string; duration?: number }> = [];

vi.mock('obsidian', () => ({
  Notice: class {
    constructor(message: string, duration?: number) {
      noticeCalls.push({ message, duration });
    }
  },
  Plugin: class {},
  TFile: class {
    name: string;
    path: string;
    constructor(name: string, path?: string) {
      this.name = name;
      this.path = path || name;
    }
  },
  MarkdownView: class {
    getViewType() { return 'markdown'; }
  },
}));

const { TFile } = await import('obsidian');

function createEncryptedBodyBytes(): Uint8Array {
  const record: EncryptedFileRecord = {
    magic: new Uint8Array(MAGIC_BYTES),
    version: FORMAT_VERSION,
    providerId: 'aws-kms',
    cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
    wrappedDek: new Uint8Array(32).fill(0xAA),
    nonce: new Uint8Array(12).fill(0xBB),
    authTag: new Uint8Array(16).fill(0xCC),
    ciphertext: new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]),
  };
  return serialize(record);
}

function createFileWithFrontmatter(frontmatter: string, body: Uint8Array): ArrayBuffer {
  const frontmatterBytes = new TextEncoder().encode(frontmatter);
  const combined = new Uint8Array(frontmatterBytes.length + body.length);
  combined.set(frontmatterBytes, 0);
  combined.set(body, frontmatterBytes.length);
  return combined.buffer;
}

function createMockCryptoEngine(decryptResult: Uint8Array = new TextEncoder().encode('Decrypted content')): CryptoEngine {
  return {
    encrypt: vi.fn(),
    decrypt: vi.fn(async () => decryptResult),
  };
}

function createMockFile(name: string, path?: string) {
  return new TFile(name, path || `notes/${name}`);
}

function createMockPlugin(fileContentBuffer: ArrayBuffer) {
  const mockEditor = {
    getValue: vi.fn(() => ''),
    setValue: vi.fn(),
  };

  const mockLeaf = {
    getViewState: vi.fn(() => ({ type: 'markdown', state: { mode: 'source' } })),
    setViewState: vi.fn(),
  };

  const mockActiveView: any = {
    file: null as any,
    editor: mockEditor,
    leaf: mockLeaf,
  };

  const plugin = {
    app: {
      workspace: {
        on: vi.fn((_eventName: string, _handler: Function) => {
          return { _eventName, _handler };
        }),
        getActiveViewOfType: vi.fn(() => mockActiveView),
      },
      vault: {
        getName: vi.fn(() => 'test-vault'),
        readBinary: vi.fn(async () => fileContentBuffer),
      },
    },
    registerEvent: vi.fn(),
    _mockActiveView: mockActiveView,
    _mockEditor: mockEditor,
    _mockLeaf: mockLeaf,
  };

  return plugin;
}

function getHandler(plugin: ReturnType<typeof createMockPlugin>): Function {
  return plugin.app.workspace.on.mock.calls[0][1];
}

function createValidSettings(): PluginSettings {
  return {
    awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    encryptedNoteSuffix: '.secret.md',
    providers: [],
    vaultPolicies: [],
  };
}

describe('registerOpenHook', () => {
  let settings: PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    noticeCalls.length = 0;
    settings = createValidSettings();
  });

  it('should register a file-open event handler', () => {
    const mockPlugin = createMockPlugin(new ArrayBuffer(0));
    const mockEngine = createMockCryptoEngine();

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);

    expect(mockPlugin.registerEvent).toHaveBeenCalledTimes(1);
    expect(mockPlugin.app.workspace.on).toHaveBeenCalledWith(
      'file-open',
      expect.any(Function)
    );
  });

  it('should ignore null file', async () => {
    const mockPlugin = createMockPlugin(new ArrayBuffer(0));
    const mockEngine = createMockCryptoEngine();

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(null);

    expect(mockPlugin.app.vault.readBinary).not.toHaveBeenCalled();
  });

  it('should ignore files that do not match the encrypted suffix', async () => {
    const mockPlugin = createMockPlugin(new ArrayBuffer(0));
    const mockEngine = createMockCryptoEngine();
    const file = createMockFile('regular-note.md');

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockPlugin.app.vault.readBinary).not.toHaveBeenCalled();
  });

  it('should pass through plaintext files that match suffix but have no magic bytes', async () => {
    const plainContent = 'This is just plain markdown content';
    const plainBytes = new TextEncoder().encode(plainContent);
    const mockPlugin = createMockPlugin(plainBytes.buffer);
    const mockEngine = createMockCryptoEngine();
    const file = createMockFile('notes.secret.md');

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    // Should read the file but not attempt decryption
    expect(mockPlugin.app.vault.readBinary).toHaveBeenCalled();
    expect(mockEngine.decrypt).not.toHaveBeenCalled();
  });

  it('should decrypt encrypted body and present plaintext to editor', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const decryptedText = 'Decrypted secret content';
    const mockEngine = createMockCryptoEngine(new TextEncoder().encode(decryptedText));
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockEngine.decrypt).toHaveBeenCalled();
    expect(mockPlugin._mockEditor.setValue).toHaveBeenCalledWith(decryptedText);
  });

  it('should preserve frontmatter and decrypt only the body', async () => {
    const frontmatter = '---\ntitle: Secret Note\ntags: [secret]\n---\n';
    const encryptedBodyBytes = createEncryptedBodyBytes();
    const fileBuffer = createFileWithFrontmatter(frontmatter, encryptedBodyBytes);

    const mockPlugin = createMockPlugin(fileBuffer);
    const decryptedText = 'Decrypted body content';
    const mockEngine = createMockCryptoEngine(new TextEncoder().encode(decryptedText));
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockEngine.decrypt).toHaveBeenCalled();
    expect(mockPlugin._mockEditor.setValue).toHaveBeenCalledWith(frontmatter + decryptedText);
  });

  it('should build correct encryption context for decrypt call', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const mockEngine = createMockCryptoEngine();
    const file = createMockFile('notes.secret.md', 'notes/notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockEngine.decrypt).toHaveBeenCalledWith(
      expect.any(Object),
      {
        vaultName: 'test-vault',
        filePath: 'notes/notes.secret.md',
        formatVersion: FORMAT_VERSION,
      }
    );
  });

  it('should show error notice on decryption failure (PluginError)', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const failingEngine: CryptoEngine = {
      encrypt: vi.fn(),
      decrypt: vi.fn(async () => {
        throw new PluginError('KMS access denied', 'authorization');
      }),
    };
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, failingEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(noticeCalls.length).toBeGreaterThan(0);
    expect(noticeCalls[0].message).toContain('Access denied');
  });

  it('should set view to preview mode on decryption failure', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const failingEngine: CryptoEngine = {
      encrypt: vi.fn(),
      decrypt: vi.fn(async () => {
        throw new PluginError('KMS access denied', 'authorization');
      }),
    };
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, failingEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockPlugin._mockLeaf.setViewState).toHaveBeenCalledWith(
      expect.objectContaining({
        state: expect.objectContaining({ mode: 'preview' }),
      })
    );
  });

  it('should show generic error notice on non-PluginError failure', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const failingEngine: CryptoEngine = {
      encrypt: vi.fn(),
      decrypt: vi.fn(async () => {
        throw new Error('Network timeout');
      }),
    };
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;

    registerOpenHook(mockPlugin as any, failingEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(noticeCalls.length).toBeGreaterThan(0);
    expect(noticeCalls[0].message).toContain('Network timeout');
  });

  it('should not set editor value if content is already decrypted', async () => {
    const decryptedText = 'Already decrypted content';
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const mockEngine = createMockCryptoEngine(new TextEncoder().encode(decryptedText));
    const file = createMockFile('notes.secret.md');
    mockPlugin._mockActiveView.file = file;
    // Editor already has the decrypted content
    mockPlugin._mockEditor.getValue = vi.fn(() => decryptedText);

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockPlugin._mockEditor.setValue).not.toHaveBeenCalled();
  });

  it('should use custom suffix from settings', async () => {
    const customSettings: PluginSettings = {
      ...settings,
      encryptedNoteSuffix: '.encrypted.md',
    };
    const mockPlugin = createMockPlugin(new ArrayBuffer(0));
    const mockEngine = createMockCryptoEngine();
    const file = createMockFile('notes.secret.md');

    registerOpenHook(mockPlugin as any, mockEngine, () => customSettings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    expect(mockPlugin.app.vault.readBinary).not.toHaveBeenCalled();
  });

  it('should not modify editor if active view file does not match opened file', async () => {
    const encryptedBytes = createEncryptedBodyBytes();
    const mockPlugin = createMockPlugin(encryptedBytes.buffer);
    const mockEngine = createMockCryptoEngine();
    const file = createMockFile('notes.secret.md', 'notes/notes.secret.md');
    // Active view has a different file
    mockPlugin._mockActiveView.file = createMockFile('other.secret.md', 'other/other.secret.md');

    registerOpenHook(mockPlugin as any, mockEngine, () => settings);
    const handler = getHandler(mockPlugin);

    await handler(file);

    // Should decrypt but not set editor value (wrong file in view)
    expect(mockEngine.decrypt).toHaveBeenCalled();
    expect(mockPlugin._mockEditor.setValue).not.toHaveBeenCalled();
  });
});
