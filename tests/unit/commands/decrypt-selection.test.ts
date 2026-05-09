/**
 * Unit tests for the "Decrypt selection with AWS KMS" command.
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerDecryptSelectionCommand } from '../../../src/commands/decrypt-selection';
import { encodeInlineBlock } from '../../../src/format/inline-codec';
import { serialize } from '../../../src/format/serializer';
import { MAGIC_BYTES, FORMAT_VERSION, NOTICE_DURATION_MS } from '../../../src/constants';
import { PluginError } from '../../../src/providers/errors';
import type {
  CryptoEngine,
  EncryptedFileRecord,
  EncryptionContext,
  PluginSettings,
} from '../../../src/types';

// Track Notice calls
const noticeInstances: Array<{ message: string; duration?: number }> = [];

vi.mock('obsidian', () => ({
  Notice: vi.fn().mockImplementation((message: string, duration?: number) => {
    noticeInstances.push({ message, duration });
  }),
  Plugin: class {},
}));

/**
 * Creates a mock Obsidian editor.
 */
function createMockEditor(selection = '') {
  return {
    getSelection: vi.fn(() => selection),
    replaceSelection: vi.fn(),
    getCursor: vi.fn(() => ({ line: 0, ch: 0 })),
  };
}

/**
 * Creates a mock MarkdownView with a file.
 */
function createMockView(filePath = 'notes/secret.md') {
  return {
    file: { path: filePath },
  };
}

/**
 * Creates a mock Plugin instance.
 */
function createMockPlugin() {
  const commands: Array<{ id: string; name: string; editorCallback: Function }> = [];
  return {
    app: {
      vault: {
        getName: vi.fn(() => 'test-vault'),
      },
    },
    addCommand: vi.fn((cmd: any) => {
      commands.push(cmd);
    }),
    _commands: commands,
  };
}

/**
 * Creates a mock CryptoEngine.
 */
function createMockCryptoEngine(decryptResult?: Uint8Array, decryptError?: Error) {
  return {
    encrypt: vi.fn(),
    decrypt: vi.fn(async () => {
      if (decryptError) throw decryptError;
      return decryptResult ?? new TextEncoder().encode('decrypted text');
    }),
  } as unknown as CryptoEngine;
}

/**
 * Creates default plugin settings.
 */
function createSettings(): PluginSettings {
  return {
    awsCmkArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    encryptedNoteSuffix: '.secret.md',
    providers: [],
    vaultPolicies: [],
  };
}

/**
 * Creates a valid encrypted inline block string for testing.
 */
function createValidEncryptedBlock(): string {
  const record: EncryptedFileRecord = {
    magic: new Uint8Array(MAGIC_BYTES),
    version: FORMAT_VERSION,
    providerId: 'aws-kms',
    cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    wrappedDek: new Uint8Array(32).fill(0xab),
    nonce: new Uint8Array(12).fill(0xcd),
    authTag: new Uint8Array(16).fill(0xef),
    ciphertext: new TextEncoder().encode('encrypted content'),
  };
  const serialized = serialize(record);
  return encodeInlineBlock(serialized);
}

describe('registerDecryptSelectionCommand', () => {
  let plugin: ReturnType<typeof createMockPlugin>;
  let cryptoEngine: CryptoEngine;
  let getSettings: () => PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    noticeInstances.length = 0;
    plugin = createMockPlugin();
    cryptoEngine = createMockCryptoEngine();
    getSettings = () => createSettings();
  });

  it('should register a command with correct id and name', () => {
    registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);

    expect(plugin.addCommand).toHaveBeenCalledTimes(1);
    const cmd = plugin._commands[0];
    expect(cmd.id).toBe('decrypt-selection-aws-kms');
    expect(cmd.name).toBe('Decrypt selection with AWS KMS');
  });

  describe('editorCallback', () => {
    let executeCommand: (editor: any, view: any) => Promise<void>;

    beforeEach(() => {
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;
    });

    it('should show notice when selection is empty', async () => {
      const editor = createMockEditor('');
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'No text selected',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show notice when selection has no valid encrypted block', async () => {
      const editor = createMockEditor('This is just plain text without any encrypted block');
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'No valid encrypted block in selection',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should decrypt valid encrypted block and replace selection', async () => {
      const encryptedBlock = createValidEncryptedBlock();
      const expectedPlaintext = 'decrypted text';
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(cryptoEngine.decrypt).toHaveBeenCalled();
      expect(editor.replaceSelection).toHaveBeenCalledWith(expectedPlaintext);
    });

    it('should pass correct encryption context to cryptoEngine.decrypt', async () => {
      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView('clients/acme/notes.md');

      await executeCommand(editor, view);

      expect(cryptoEngine.decrypt).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          vaultName: 'test-vault',
          filePath: 'clients/acme/notes.md',
          formatVersion: FORMAT_VERSION,
        })
      );
    });

    it('should show "Integrity check failed" notice on integrity error', async () => {
      const integrityError = new PluginError('Auth tag mismatch', 'integrity');
      cryptoEngine = createMockCryptoEngine(undefined, integrityError);
      plugin = createMockPlugin();
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;

      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'Integrity check failed',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show "Decryption request timed out" notice on timeout error', async () => {
      const timeoutError = new PluginError('KMS call timed out', 'timeout');
      cryptoEngine = createMockCryptoEngine(undefined, timeoutError);
      plugin = createMockPlugin();
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;

      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'Decryption request timed out',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show provider error message on other PluginError categories', async () => {
      const networkError = new PluginError('Network connection failed', 'network');
      cryptoEngine = createMockCryptoEngine(undefined, networkError);
      plugin = createMockPlugin();
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;

      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'Network connection failed',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show error message on generic Error', async () => {
      const genericError = new Error('Something went wrong');
      cryptoEngine = createMockCryptoEngine(undefined, genericError);
      plugin = createMockPlugin();
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;

      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(noticeInstances).toContainEqual({
        message: 'Something went wrong',
        duration: NOTICE_DURATION_MS,
      });
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should not modify editor on any error', async () => {
      const error = new PluginError('KMS error', 'credential');
      cryptoEngine = createMockCryptoEngine(undefined, error);
      plugin = createMockPlugin();
      registerDecryptSelectionCommand(plugin as any, cryptoEngine, getSettings);
      executeCommand = plugin._commands[0].editorCallback;

      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should handle view with no file gracefully', async () => {
      const encryptedBlock = createValidEncryptedBlock();
      const editor = createMockEditor(encryptedBlock);
      const view = { file: null };

      await executeCommand(editor, view);

      expect(cryptoEngine.decrypt).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          filePath: '',
        })
      );
      expect(editor.replaceSelection).toHaveBeenCalledWith('decrypted text');
    });

    it('should show notice for format errors during parsing', async () => {
      // Create a block with invalid base64 content that will fail during parse
      const invalidBlock = '```ocke-v1\nSW52YWxpZA==\n```';
      const editor = createMockEditor(invalidBlock);
      const view = createMockView();

      await executeCommand(editor, view);

      // The parse will fail because the decoded bytes won't have valid magic bytes
      expect(noticeInstances.length).toBeGreaterThan(0);
      expect(editor.replaceSelection).not.toHaveBeenCalled();
    });
  });
});
