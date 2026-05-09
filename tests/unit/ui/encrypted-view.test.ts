/**
 * Unit tests for the encrypted file read-only view.
 *
 * Tests:
 * - View type and display text
 * - Error banner rendering with message
 * - Raw content displayed as base64
 * - registerEncryptedFileView registers the view type
 * - openEncryptedFileView creates a leaf and sets content
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  EncryptedFileView,
  ENCRYPTED_FILE_VIEW_TYPE,
  registerEncryptedFileView,
  openEncryptedFileView,
  showEncryptedFileError,
} from '../../../src/ui/encrypted-view';
import { Plugin, WorkspaceLeaf } from 'obsidian';
import { PluginError } from '../../../src/providers/errors';

describe('EncryptedFileView', () => {
  let view: EncryptedFileView;
  let leaf: WorkspaceLeaf;

  beforeEach(() => {
    leaf = new WorkspaceLeaf();
    view = new EncryptedFileView(leaf);
  });

  describe('getViewType', () => {
    it('returns the encrypted-file-view type', () => {
      expect(view.getViewType()).toBe('encrypted-file-view');
    });
  });

  describe('getDisplayText', () => {
    it('returns default text when no file path is set', () => {
      expect(view.getDisplayText()).toBe('Encrypted File (Read-Only)');
    });

    it('returns file path in display text when set', () => {
      const rawContent = new Uint8Array([1, 2, 3]);
      view.setContent('notes/secret.md', 'KMS timeout', rawContent);
      expect(view.getDisplayText()).toBe('Encrypted: notes/secret.md');
    });
  });

  describe('getIcon', () => {
    it('returns lock icon', () => {
      expect(view.getIcon()).toBe('lock');
    });
  });

  describe('setContent', () => {
    it('stores file path, error message, and base64-encoded content', () => {
      const rawContent = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      view.setContent('path/to/file.md', 'Decryption failed: KMS timeout', rawContent);

      const state = view.getState();
      expect(state.filePath).toBe('path/to/file.md');
      expect(state.errorMessage).toBe('Decryption failed: KMS timeout');
      expect(state.rawContentBase64).toBe(btoa('Hello'));
    });

    it('handles empty content', () => {
      const rawContent = new Uint8Array(0);
      view.setContent('file.md', 'Error', rawContent);

      const state = view.getState();
      expect(state.rawContentBase64).toBe('');
    });
  });

  describe('getState / setState', () => {
    it('round-trips state correctly', async () => {
      const rawContent = new Uint8Array([0x4F, 0x43, 0x4B, 0x45]);
      view.setContent('test.secret.md', 'Auth failed', rawContent);

      const state = view.getState();
      const newView = new EncryptedFileView(leaf);
      await newView.setState(state, {});

      expect(newView.getState()).toEqual(state);
    });

    it('handles partial state updates', async () => {
      view.setContent('original.md', 'Original error', new Uint8Array([1]));
      await view.setState({ errorMessage: 'Updated error' }, {});

      const state = view.getState();
      expect(state.filePath).toBe('original.md');
      expect(state.errorMessage).toBe('Updated error');
    });
  });

  describe('ENCRYPTED_FILE_VIEW_TYPE', () => {
    it('is the expected string constant', () => {
      expect(ENCRYPTED_FILE_VIEW_TYPE).toBe('encrypted-file-view');
    });
  });
});

describe('registerEncryptedFileView', () => {
  it('registers the view type with the plugin', () => {
    const plugin = new Plugin();
    registerEncryptedFileView(plugin as any);

    expect(plugin.registerView).toHaveBeenCalledWith(
      ENCRYPTED_FILE_VIEW_TYPE,
      expect.any(Function)
    );
  });

  it('factory function creates an EncryptedFileView instance', () => {
    const plugin = new Plugin();
    registerEncryptedFileView(plugin as any);

    const factory = (plugin.registerView as any).mock.calls[0][1];
    const leaf = new WorkspaceLeaf();
    const instance = factory(leaf);
    expect(instance).toBeInstanceOf(EncryptedFileView);
  });
});

describe('openEncryptedFileView', () => {
  it('detaches existing views, creates a leaf, and sets content', async () => {
    const plugin = new Plugin();
    const mockLeaf = new WorkspaceLeaf();
    const mockView = new EncryptedFileView(mockLeaf);
    mockLeaf.view = mockView;
    mockLeaf.setViewState = vi.fn().mockResolvedValue(undefined);

    (plugin.app.workspace.getLeaf as any).mockReturnValue(mockLeaf);

    const rawContent = new Uint8Array([10, 20, 30]);
    await openEncryptedFileView(
      plugin as any,
      'secret/note.md',
      'Decryption failed: access denied',
      rawContent
    );

    expect(plugin.app.workspace.detachLeavesOfType).toHaveBeenCalledWith(
      ENCRYPTED_FILE_VIEW_TYPE
    );
    expect(plugin.app.workspace.getLeaf).toHaveBeenCalledWith(true);
    expect(mockLeaf.setViewState).toHaveBeenCalledWith({
      type: ENCRYPTED_FILE_VIEW_TYPE,
      active: true,
    });
    expect(plugin.app.workspace.revealLeaf).toHaveBeenCalledWith(mockLeaf);

    // Verify content was set on the view
    const state = mockView.getState();
    expect(state.filePath).toBe('secret/note.md');
    expect(state.errorMessage).toBe('Decryption failed: access denied');
  });
});


describe('showEncryptedFileError', () => {
  it('opens the encrypted view with error category and message for PluginError', async () => {
    const plugin = new Plugin();
    const mockLeaf = new WorkspaceLeaf();
    const mockView = new EncryptedFileView(mockLeaf);
    mockLeaf.view = mockView;
    mockLeaf.setViewState = vi.fn().mockResolvedValue(undefined);

    (plugin.app.workspace.getLeaf as any).mockReturnValue(mockLeaf);

    const rawContent = new Uint8Array([0x4F, 0x43, 0x4B, 0x45]);
    const error = new PluginError(
      'KMS request timed out',
      'timeout',
      'aws-kms',
      'arn:aws:kms:us-east-1:123456789012:key/abc',
      'notes/secret.md'
    );

    await showEncryptedFileError(plugin as any, 'notes/secret.md', rawContent, error);

    const state = mockView.getState();
    expect(state.filePath).toBe('notes/secret.md');
    expect(state.errorMessage).toBe('[timeout] KMS request timed out');
  });

  it('opens the encrypted view with plain message for generic Error', async () => {
    const plugin = new Plugin();
    const mockLeaf = new WorkspaceLeaf();
    const mockView = new EncryptedFileView(mockLeaf);
    mockLeaf.view = mockView;
    mockLeaf.setViewState = vi.fn().mockResolvedValue(undefined);

    (plugin.app.workspace.getLeaf as any).mockReturnValue(mockLeaf);

    const rawContent = new Uint8Array([1, 2, 3]);
    const error = new Error('Something went wrong');

    await showEncryptedFileError(plugin as any, 'file.md', rawContent, error);

    const state = mockView.getState();
    expect(state.filePath).toBe('file.md');
    expect(state.errorMessage).toBe('Something went wrong');
  });

  it('uses default message when error has no message', async () => {
    const plugin = new Plugin();
    const mockLeaf = new WorkspaceLeaf();
    const mockView = new EncryptedFileView(mockLeaf);
    mockLeaf.view = mockView;
    mockLeaf.setViewState = vi.fn().mockResolvedValue(undefined);

    (plugin.app.workspace.getLeaf as any).mockReturnValue(mockLeaf);

    const rawContent = new Uint8Array([]);
    const error = new Error('');

    await showEncryptedFileError(plugin as any, 'empty.md', rawContent, error);

    const state = mockView.getState();
    expect(state.errorMessage).toBe('Decryption failed');
  });

  it('detaches existing views and reveals the new leaf', async () => {
    const plugin = new Plugin();
    const mockLeaf = new WorkspaceLeaf();
    const mockView = new EncryptedFileView(mockLeaf);
    mockLeaf.view = mockView;
    mockLeaf.setViewState = vi.fn().mockResolvedValue(undefined);

    (plugin.app.workspace.getLeaf as any).mockReturnValue(mockLeaf);

    const rawContent = new Uint8Array([10, 20]);
    const error = new PluginError('Access denied', 'authorization');

    await showEncryptedFileError(plugin as any, 'denied.md', rawContent, error);

    expect(plugin.app.workspace.detachLeavesOfType).toHaveBeenCalledWith(
      ENCRYPTED_FILE_VIEW_TYPE
    );
    expect(plugin.app.workspace.getLeaf).toHaveBeenCalledWith(true);
    expect(plugin.app.workspace.revealLeaf).toHaveBeenCalledWith(mockLeaf);
  });
});
