/**
 * Command: "Wrap selection in secret block"
 *
 * Wraps the current editor selection in %%secret-start%% / %%secret-end%% markers.
 * If multiple keys are configured, shows a picker to choose which key alias to use.
 * The actual encryption happens transparently via the adapter patch on save.
 */

import { App, Editor, Notice, Plugin, MarkdownView, FuzzySuggestModal } from 'obsidian';
import type { CryptoEngine, PluginSettings } from '../types';
import { MAX_SELECTION_CHARS, NOTICE_DURATION_MS } from '../constants';
import { getKeyAliases } from '../utils/key-resolver';

export function registerEncryptSelectionCommand(
  plugin: Plugin,
  _cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'encrypt-selection-aws-kms',
    name: 'Wrap selection in secret block',
    editorCheckCallback: (checking) => {
      const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
      if (!markdownView) return false;
      if (checking) return true;

      executeWrapSelection(plugin, getSettings);
      return true;
    },
  });
}

function executeWrapSelection(plugin: Plugin, getSettings: () => PluginSettings): void {
  const markdownView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
  if (!markdownView) {
    new Notice('No active editor', NOTICE_DURATION_MS);
    return;
  }

  const editor: Editor = markdownView.editor;
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

  const settings = getSettings();
  const aliases = getKeyAliases(settings);

  if (aliases.length <= 1) {
    // Single key or no keys — wrap with alias if available
    const alias = aliases.length === 1 && aliases[0] !== 'default' ? aliases[0] : undefined;
    wrapWithAlias(editor, selection, alias);
  } else {
    // Multiple keys — show picker
    new KeyPickerModal(plugin.app, aliases, (chosen) => {
      wrapWithAlias(editor, selection, chosen);
    }).open();
  }
}

function wrapWithAlias(editor: Editor, selection: string, alias: string | undefined): void {
  const startMarker = alias ? `%%secret-start:${alias}%%` : '%%secret-start%%';
  const secretBlock = `${startMarker}\n${selection}\n%%secret-end%%`;
  editor.replaceSelection(secretBlock);
}

/**
 * Fuzzy suggest modal for picking a key alias.
 */
class KeyPickerModal extends FuzzySuggestModal<string> {
  private readonly aliases: string[];
  private readonly onChoose: (alias: string) => void;

  constructor(app: App, aliases: string[], onChoose: (alias: string) => void) {
    super(app);
    this.aliases = aliases;
    this.onChoose = onChoose;
    this.setPlaceholder('Choose encryption key...');
  }

  getItems(): string[] {
    return this.aliases;
  }

  getItemText(item: string): string {
    return item;
  }

  onChooseItem(item: string): void {
    this.onChoose(item);
  }
}
