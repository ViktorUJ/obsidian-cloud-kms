/**
 * Command: "Unwrap secret block"
 *
 * Removes the ```secret wrapper from the selected text,
 * leaving just the plaintext content.
 *
 * Since the adapter patch handles transparent decryption,
 * this command is for manually removing the secret block markers.
 */

import { Notice, Plugin } from 'obsidian';
import type { CryptoEngine, PluginSettings } from '../types';
import { NOTICE_DURATION_MS } from '../constants';

const SECRET_BLOCK_REGEX = /^%%secret-start%%\n([\s\S]*?)\n%%secret-end%%$/;

/**
 * Register the "Unwrap secret block" command.
 */
export function registerDecryptSelectionCommand(
  plugin: Plugin,
  _cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'decrypt-selection-aws-kms',
    name: 'Unwrap secret block',
    editorCallback: (editor) => {
      const selection = editor.getSelection();

      if (!selection || selection.length === 0) {
        new Notice('No text selected', NOTICE_DURATION_MS);
        return;
      }

      const match = SECRET_BLOCK_REGEX.exec(selection.trim());
      if (!match) {
        new Notice('Selection is not a %%secret-start%%...%%secret-end%% block', NOTICE_DURATION_MS);
        return;
      }

      // Replace selection with just the inner content
      editor.replaceSelection(match[1]);
    },
  });
}
