/**
 * Unit tests for the "Encrypt selection with AWS KMS" command.
 * Validates: Requirements 1.1, 1.2, 1.5, 1.6, 1.7, 1.8
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerEncryptSelectionCommand } from '../../../src/commands/encrypt-selection';
import type { CryptoEngine, EncryptionContext, EncryptedFileRecord, PluginSettings } from '../../../src/types';
import { MAGIC_BYTES, FORMAT_VERSION, MAX_SELECTION_CHARS, NOTICE_DURATION_MS } from '../../../src/constants';

// Track Notice calls via the mock module
const noticeCalls: Array<{ message: string; duration?: number }> = [];

vi.mock('obsidian', () => ({
  Notice: class {
    constructor(message: string, duration?: number) {
      noticeCalls.push({ message, duration });
    }
  },
  MarkdownView: class {
    static viewType = 'markdown';
  },
  Plugin: class {},
}));

function createMockEditor(selection = '') {
  return {
    getSelection: vi.fn(() => selection),
    replaceSelection: vi.fn(),
  };
}

function createMockMarkdownView(editor: ReturnType<typeof createMockEditor>, file = { path: 'notes/test.md' }) {
  return {
    editor,
    file,
    getViewType: () => 'markdown',
  };
}

function createMockPlugin(markdownView: ReturnType<typeof createMockMarkdownView> | null) {
  const commands: Array<{ id: string; name: string; editorCheckCallback: Function }> = [];

  return {
    app: {
      workspace: {
        getActiveViewOfType: vi.fn(() => markdownView),
      },
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

describe('registerEncryptSelectionCommand', () => {
  let mockEditor: ReturnType<typeof createMockEditor>;
  let mockView: ReturnType<typeof createMockMarkdownView>;
  let mockPlugin: ReturnType<typeof createMockPlugin>;
  let mockEngine: CryptoEngine;
  let settings: PluginSettings;

  beforeEach(() => {
    vi.clearAllMocks();
    noticeCalls.length = 0;
    mockEditor = createMockEditor('Hello, world!');
    mockView = createMockMarkdownView(mockEditor);
    mockPlugin = createMockPlugin(mockView);
    mockEngine = createMockCryptoEngine();
    settings = createValidSettings();
  });

  it('should register a command with correct id and name', () => {
    registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => settings);

    expect(mockPlugin.addCommand).toHaveBeenCalledTimes(1);
    const cmd = mockPlugin._commands[0];
    expect(cmd.id).toBe('encrypt-selection-aws-kms');
    expect(cmd.name).toBe('Encrypt selection with AWS KMS');
  });

  it('should use editorCheckCallback for command registration', () => {
    registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => settings);

    const cmd = mockPlugin._commands[0];
    expect(cmd.editorCheckCallback).toBeDefined();
  });

  describe('editorCheckCallback - checking mode', () => {
    it('should return true when a markdown view is active', () => {
      registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => settings);
      const cmd = mockPlugin._commands[0];

      const result = cmd.editorCheckCallback(true, mockEditor, mockView);
      expect(result).toBe(true);
    });

    it('should return false when no markdown view is active', () => {
      const noViewPlugin = createMockPlugin(null);
      registerEncryptSelectionCommand(noViewPlugin as any, mockEngine, () => settings);
      const cmd = noViewPlugin._commands[0];

      const result = cmd.editorCheckCallback(true, mockEditor, mockView);
      expect(result).toBe(false);
    });
  });

  describe('editorCheckCallback - execution mode', () => {
    it('should show notice when no active editor', async () => {
      // Simulate: checking passes (view exists), but by execution time view is gone
      const changingPlugin = createMockPlugin(mockView);
      registerEncryptSelectionCommand(changingPlugin as any, mockEngine, () => settings);
      const cmd = changingPlugin._commands[0];

      // First call returns view (for checking), second returns null (for execution)
      changingPlugin.app.workspace.getActiveViewOfType
        .mockReturnValueOnce(mockView)
        .mockReturnValueOnce(null);

      cmd.editorCheckCallback(false, mockEditor, mockView);

      // Wait for async execution
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'No active editor',
        duration: NOTICE_DURATION_MS,
      });
    });

    it('should show notice when selection is empty', async () => {
      const emptyEditor = createMockEditor('');
      const emptyView = createMockMarkdownView(emptyEditor);
      const plugin = createMockPlugin(emptyView);
      registerEncryptSelectionCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.editorCheckCallback(false, emptyEditor, emptyView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'No text selected. Select text to encrypt.',
        duration: NOTICE_DURATION_MS,
      });
      expect(emptyEditor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show notice when selection exceeds max chars', async () => {
      const largeSelection = 'x'.repeat(MAX_SELECTION_CHARS + 1);
      const largeEditor = createMockEditor(largeSelection);
      const largeView = createMockMarkdownView(largeEditor);
      const plugin = createMockPlugin(largeView);
      registerEncryptSelectionCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.editorCheckCallback(false, largeEditor, largeView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls.length).toBe(1);
      expect(noticeCalls[0].message).toContain('Selection too large');
      expect(noticeCalls[0].duration).toBe(NOTICE_DURATION_MS);
      expect(largeEditor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show notice when CMK ARN is not configured', async () => {
      const noArnSettings: PluginSettings = { ...settings, awsCmkArn: '' };
      registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => noArnSettings);
      const cmd = mockPlugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, mockView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'Configure a valid AWS KMS Key ARN in plugin settings.',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEditor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should show notice when CMK ARN is invalid format', async () => {
      const badArnSettings: PluginSettings = { ...settings, awsCmkArn: 'not-a-valid-arn' };
      registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => badArnSettings);
      const cmd = mockPlugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, mockView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'Configure a valid AWS KMS Key ARN in plugin settings.',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEditor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should encrypt selection and replace with inline block on success', async () => {
      registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => settings);
      const cmd = mockPlugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, mockView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(mockEngine.encrypt).toHaveBeenCalled();
      expect(mockEditor.replaceSelection).toHaveBeenCalledTimes(1);

      const replacedContent = mockEditor.replaceSelection.mock.calls[0][0];
      expect(replacedContent).toContain('```ocke-v1');
      expect(replacedContent).toMatch(/```$/);
    });

    it('should pass correct arguments to cryptoEngine.encrypt', async () => {
      registerEncryptSelectionCommand(mockPlugin as any, mockEngine, () => settings);
      const cmd = mockPlugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, mockView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        new TextEncoder().encode('Hello, world!'),
        'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
        'aws-kms',
        {
          vaultName: 'test-vault',
          filePath: 'notes/test.md',
          formatVersion: FORMAT_VERSION,
        }
      );
    });

    it('should show notice and not modify editor when cryptoEngine.encrypt fails', async () => {
      const failingEngine: CryptoEngine = {
        encrypt: vi.fn(async () => { throw new Error('KMS timeout'); }),
        decrypt: vi.fn(),
      };

      registerEncryptSelectionCommand(mockPlugin as any, failingEngine, () => settings);
      const cmd = mockPlugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, mockView);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(noticeCalls).toContainEqual({
        message: 'Encryption error: KMS timeout',
        duration: NOTICE_DURATION_MS,
      });
      expect(mockEditor.replaceSelection).not.toHaveBeenCalled();
    });

    it('should handle selection at exactly MAX_SELECTION_CHARS', async () => {
      const maxSelection = 'a'.repeat(MAX_SELECTION_CHARS);
      const maxEditor = createMockEditor(maxSelection);
      const maxView = createMockMarkdownView(maxEditor);
      const plugin = createMockPlugin(maxView);
      registerEncryptSelectionCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.editorCheckCallback(false, maxEditor, maxView);

      await new Promise(resolve => setTimeout(resolve, 50));

      // Should succeed (not show size error)
      expect(mockEngine.encrypt).toHaveBeenCalled();
      expect(maxEditor.replaceSelection).toHaveBeenCalled();
    });

    it('should handle file being null gracefully', async () => {
      const noFileView = createMockMarkdownView(mockEditor, null as any);
      (noFileView as any).file = null;
      const plugin = createMockPlugin(noFileView);
      registerEncryptSelectionCommand(plugin as any, mockEngine, () => settings);
      const cmd = plugin._commands[0];

      cmd.editorCheckCallback(false, mockEditor, noFileView);

      await new Promise(resolve => setTimeout(resolve, 50));

      // Should still work, using empty string for filePath
      expect(mockEngine.encrypt).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        settings.awsCmkArn,
        'aws-kms',
        expect.objectContaining({ filePath: '' })
      );
    });
  });
});
