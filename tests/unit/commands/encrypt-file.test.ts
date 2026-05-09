/**
 * Unit tests for the "Encrypt current file with AWS KMS" command.
 * Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerEncryptFileCommand } from '../../../src/commands/encrypt-file';
import type { CryptoEngine, EncryptionContext, EncryptedFileRecord, PluginSettings } from '../../../src/types';
import { MAGIC_BYTES, FORMAT_VERSION, NOTICE_DURATION_MS } from '../../../src/constants';

// Track Notice calls via the mock module
const noticeCalls: Array<{ message: string; duration?: number }> = [];

vi.mock('obsidian', () => ({
  Notice: class {
    constructor(message: string, duration?: number) {
      noticeCalls.push({ message, duration });
    }
  },
  Plugin: class {},
  TFile: class {
    path: string = '';
    name: string = '';
    extension: string = '';
  },
}));

function createMockCryptoEngine(): CryptoEngine {
  return {
    encrypt: vi.fn(async (plaintext: Uint8Array, cmkId: string, providerId: string, _context: EncryptionContext): Promise<EncryptedFileRecord> => {
      return {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId,
        cmkId,
        wrappedDek: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
        authTag: new Uint8Array(16).fill(0xCC),
        ciphertext: new Uint8Array(plaintext.length).fill(0xDD),
      };
    }),
    decrypt: vi.fn(),
  };
}

function createValidSettings(): PluginSettings {
  return {
    awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    encryptedNoteSuffix: '.secret.md',
    providers: [],
    vaultPolicies: [],
  };
}

function createMockFile(name: string, path: string, extension: string) {
  return {
    path,
    name,
    extension,
    basename: name.replace(`.${extension}`, ''),
  };
}

function createMockPlugin(activeFile: any) {
  const commands: Array<{ id: string; name: string; callback: Function }> = [];

  return {
    app: {
      workspace: {
        getActiveFile: vi.fn(() => activeFile),
      },
      vault: {
        getName: vi.fn(() => 'test-vault'),
        read: vi.fn(async () => '---\ntitle: Test\n---\nHello body content'),
        readBinary: vi.fn(async () => new ArrayBuffer(100)),
        rename: vi.fn(async () => {}),
        getAbstractFileByPath: vi.fn((path: string) => activeFile ? { ...activeFile, path } : null),
        adapter: {
          writeBinary: vi.fn(async () => {}),
          rename: vi.fn(async () => {}),
          remove: vi.fn(async () => {}),
        },
      },
    },
    addCommand: vi.fn((cmd: any) => {
      commands.push(cmd);
    }),
    _commands: commands,
  };
}

describe('registerEncryptFileCommand', () => {
  let mockEngine: CryptoEngine;
  let settings: PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    noticeCalls.length = 0;
    mockEngine = createMockCryptoEngine();
    settings = createValidSettings();
  });

  it('should register a command with correct id and name', () => {
    const file = createMockFile('test.md', 'notes/test.md', 'md');
    const plugin = createMockPlugin(file);
    registerEncryptFileCommand(plugin as any, mockEngine, () => settings);

    expect(plugin.addCommand).toHaveBeenCalledTimes(1);
    const cmd = plugin._commands[0];
    expect(cmd.id).toBe('encrypt-current-file-aws-kms');
    expect(cmd.name).toBe('Encrypt current file with AWS KMS');
  });

  it('should use callback (not editorCheckCallback) for command registration', () => {
    const file = createMockFile('test.md', 'notes/test.md', 'md');
    const plugin = createMockPlugin(file);
    registerEncryptFileCommand(plugin as any, mockEngine, () => settings);

    const cmd = plugin._commands[0];
    expect(cmd.callback).toBeDefined();
  });

  describe('no active file', () => {
    it('should show notice when no active file', async () => {
      const plugin = createMockPlugin(null);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'No active file',
        duration: NOTICE_DURATION_MS,
      });
    });
  });

  describe('already encrypted files', () => {
    it('should show notice when note already has encrypted suffix', async () => {
      const file = createMockFile('report.secret.md', 'notes/report.secret.md', 'md');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'File is already encrypted',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEngine.encrypt).not.toHaveBeenCalled();
    });

    it('should show notice when attachment already has .enc extension', async () => {
      const file = createMockFile('screenshot.enc.png', 'assets/screenshot.enc.png', 'png');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'File is already encrypted',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEngine.encrypt).not.toHaveBeenCalled();
    });
  });

  describe('invalid CMK ARN', () => {
    it('should show notice when CMK ARN is not configured', async () => {
      const file = createMockFile('test.md', 'notes/test.md', 'md');
      const plugin = createMockPlugin(file);
      const noArnSettings = { ...settings, awsCmkArn: '' };
      registerEncryptFileCommand(plugin as any, mockEngine, () => noArnSettings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'Configure a valid AWS KMS Key ARN in plugin settings.',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEngine.encrypt).not.toHaveBeenCalled();
    });
  });

  describe('note encryption', () => {
    it('should encrypt note body and rename with suffix', async () => {
      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should have called encrypt
      expect(mockEngine.encrypt).toHaveBeenCalled();

      // Should have renamed the file
      expect(plugin.app.vault.rename).toHaveBeenCalledWith(
        file,
        'notes/report.secret.md'
      );

      // Should have written encrypted content
      expect(plugin.app.vault.adapter.writeBinary).toHaveBeenCalledWith(
        'notes/report.secret.md',
        expect.any(Uint8Array)
      );
    });

    it('should preserve frontmatter and encrypt only body', async () => {
      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);
      plugin.app.vault.read.mockResolvedValue('---\ntitle: Test\n---\nBody content here');
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // The encrypt call should receive only the body bytes
      const encoder = new TextEncoder();
      const expectedBody = encoder.encode('Body content here');
      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        expectedBody,
        settings.awsCmkArn,
        'aws-kms',
        {
          vaultName: 'test-vault',
          filePath: 'notes/report.secret.md',
          formatVersion: FORMAT_VERSION,
        }
      );

      // Written content should start with frontmatter
      const writtenBytes = plugin.app.vault.adapter.writeBinary.mock.calls[0][1] as Uint8Array;
      const writtenContent = new TextDecoder().decode(writtenBytes);
      expect(writtenContent).toMatch(/^---\ntitle: Test\n---\n/);
      expect(writtenContent).toContain('```ocke-v1');
    });

    it('should encrypt entire content when no frontmatter', async () => {
      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);
      plugin.app.vault.read.mockResolvedValue('Just plain content without frontmatter');
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // The encrypt call should receive the entire content as body
      const encoder = new TextEncoder();
      const expectedBody = encoder.encode('Just plain content without frontmatter');
      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        expectedBody,
        settings.awsCmkArn,
        'aws-kms',
        expect.any(Object)
      );

      // Written content should NOT start with frontmatter
      const writtenBytes = plugin.app.vault.adapter.writeBinary.mock.calls[0][1] as Uint8Array;
      const writtenContent = new TextDecoder().decode(writtenBytes);
      expect(writtenContent).toMatch(/^```ocke-v1/);
    });

    it('should use encryption context with new path', async () => {
      const file = createMockFile('report.md', 'docs/report.md', 'md');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        settings.awsCmkArn,
        'aws-kms',
        {
          vaultName: 'test-vault',
          filePath: 'docs/report.secret.md',
          formatVersion: FORMAT_VERSION,
        }
      );
    });
  });

  describe('attachment encryption', () => {
    it('should encrypt attachment and rename with .enc prefix', async () => {
      const file = createMockFile('screenshot.png', 'assets/screenshot.png', 'png');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should have called encrypt with the binary content
      expect(mockEngine.encrypt).toHaveBeenCalled();

      // Should have renamed the file
      expect(plugin.app.vault.rename).toHaveBeenCalledWith(
        file,
        'assets/screenshot.enc.png'
      );

      // Should have written encrypted binary content
      expect(plugin.app.vault.adapter.writeBinary).toHaveBeenCalledWith(
        'assets/screenshot.enc.png',
        expect.any(Uint8Array)
      );
    });

    it('should encrypt entire attachment content', async () => {
      const file = createMockFile('photo.jpg', 'images/photo.jpg', 'jpg');
      const plugin = createMockPlugin(file);
      const binaryContent = new ArrayBuffer(256);
      new Uint8Array(binaryContent).fill(0x42);
      plugin.app.vault.readBinary.mockResolvedValue(binaryContent);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should encrypt the full binary content
      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        new Uint8Array(256).fill(0x42),
        settings.awsCmkArn,
        'aws-kms',
        expect.objectContaining({
          filePath: 'images/photo.enc.jpg',
        })
      );
    });
  });

  describe('failure and rollback', () => {
    it('should show error notice on encryption failure', async () => {
      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);

      // Make encrypt fail
      const failingEngine: CryptoEngine = {
        encrypt: vi.fn(async () => { throw new Error('KMS unavailable'); }),
        decrypt: vi.fn(),
      };

      registerEncryptFileCommand(plugin as any, failingEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should show error notice
      expect(noticeCalls.some(n => n.message.includes('KMS unavailable'))).toBe(true);
    });

    it('should rollback rename when write fails after rename', async () => {
      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);

      // Let encrypt succeed but write fail
      let renameCallCount = 0;
      plugin.app.vault.rename.mockImplementation(async () => {
        renameCallCount++;
        // First rename succeeds, second (rollback) also succeeds
      });
      plugin.app.vault.adapter.writeBinary.mockRejectedValue(new Error('Disk full'));

      // Return the file when looking up by new path (for rollback)
      const { TFile: MockTFile } = await import('obsidian');
      const renamedFile = Object.create(MockTFile.prototype);
      Object.assign(renamedFile, { ...file, path: 'notes/report.secret.md' });
      plugin.app.vault.getAbstractFileByPath.mockReturnValue(renamedFile);

      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should show error notice
      expect(noticeCalls.some(n => n.message.includes('Disk full'))).toBe(true);

      // Should attempt to rename back (2 calls: initial rename + rollback rename)
      expect(renameCallCount).toBe(2);
    });

    it('should show notice on timeout', async () => {
      vi.useFakeTimers();

      const file = createMockFile('report.md', 'notes/report.md', 'md');
      const plugin = createMockPlugin(file);

      // Make encrypt hang (never resolve)
      const hangingEngine: CryptoEngine = {
        encrypt: vi.fn(() => new Promise(() => {})), // never resolves
        decrypt: vi.fn(),
      };

      registerEncryptFileCommand(plugin as any, hangingEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();

      // Advance past the 30s timeout
      await vi.advanceTimersByTimeAsync(31000);

      vi.useRealTimers();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls.some(n => n.message.includes('timed out'))).toBe(true);
    });
  });

  describe('file name computation', () => {
    it('should handle note in root directory', async () => {
      const file = createMockFile('test.md', 'test.md', 'md');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(plugin.app.vault.rename).toHaveBeenCalledWith(
        file,
        'test.secret.md'
      );
    });

    it('should handle attachment with no extension', async () => {
      const file = createMockFile('LICENSE', 'LICENSE', '');
      const plugin = createMockPlugin(file);
      registerEncryptFileCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.callback();
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(plugin.app.vault.rename).toHaveBeenCalledWith(
        file,
        'LICENSE.enc'
      );
    });
  });
});
