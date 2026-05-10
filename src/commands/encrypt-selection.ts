/**
 * Command: "Wrap selection in secret block"
 *
 * Wraps the current editor selection in a ```secret fenced block.
 * The actual encryption happens transparently via the adapter patch
 * when Obsidian saves the file to disk.
 *
 * Flow:
 *   1. Check active editor exists
 *   2. Get selection → if empty, show notice
 *   3. Wrap selection in ```secret\n...\n```
 *   4. Replace selection with the wrapped block
 */

import { Notice, Plugin, MarkdownView } from 'obsidian';
import type { CryptoEngine, PluginSettings } from '../types';
import { MAX_SELECTION_CHARS, NOTICE_DURATION_MS } from '../constants';

/**
 * Register the "Wrap selection in secret block" command.
 */
export function registerEncryptSelectionCommand(
  plugin: Plugin,
  _cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'encrypt-selection-aws-kms',
    name: 'Wrap selection in secret block',
    editorCheckCallback: (checking) => {
      const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
      if (!markdownView) return false;
      if (checking) return true;

      executeWrapSelection(plugin);
      return true;
    },
  });
}

function executeWrapSelection(plugin: Plugin): void {
  const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
  if (!markdownView) {
    new Notice('No active editor', NOTICE_DURATION_MS);
    return;
  }

  const editor = markdownView.editor;
  const selection = editor.getSelection();

  if (!selection || selection.length === 0) {
    new Notice('No text selected. Select text to wrap in secret block.', NOTICE_DURATION_MS);
    return;
  }

  if (selection.length > MAX_SELECTION_CHARS) {
    new Notice(
      `Selection too large: ${selection.length} characters exceeds maximum of ${MAX_SELECTION_CHARS}.`,
      NOTICE_DURATION_MS
    );
    return;
  }

  // Wrap in %%secret-start%% / %%secret-end%% markers
  // Content inside renders as normal markdown (mermaid, code blocks, etc.)
  const secretBlock = '%%secret-start%%\n' + selection + '\n%%secret-end%%';
  editor.replaceSelection(secretBlock);
}
