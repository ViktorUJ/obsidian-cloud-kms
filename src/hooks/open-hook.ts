/**
 * Open hook — transparent decryption on file open.
 *
 * Detects when a suffix-matching encrypted note is opened, reads the raw file,
 * splits frontmatter from body, checks if body starts with MAGIC_BYTES,
 * parses and decrypts via CryptoEngine, and presents the plaintext to the editor.
 *
 * On failure: sets the view to read-only (preview) mode with an error notice.
 *
 * Uses `app.workspace.on('file-open')` to detect when a suffix-matching
 * file is opened, then reads/decrypts/sets editor content.
 */

import { Plugin, TFile, MarkdownView } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION } from '../constants';
import { matchesEncryptedSuffix } from '../policies/suffix-matcher';
import { isMagicMatch, parse } from '../format/parser';
import { PluginError } from '../providers/errors';
import { showErrorNotice, showNotice } from '../ui/notices';

/**
 * Find the end offset of the frontmatter block in raw bytes.
 * Frontmatter starts with `---\n` at offset 0 and ends with `\n---\n`.
 * Returns the byte offset immediately after the closing `\n---\n`,
 * or 0 if no valid frontmatter is found.
 */
function findFrontmatterEndOffset(data: Uint8Array): number {
  // Frontmatter must start with `---\n` (0x2D 0x2D 0x2D 0x0A)
  if (data.length < 4) return 0;
  if (data[0] !== 0x2D || data[1] !== 0x2D || data[2] !== 0x2D || data[3] !== 0x0A) {
    return 0;
  }

  // Search for closing `\n---\n` (0x0A 0x2D 0x2D 0x2D 0x0A)
  for (let i = 4; i < data.length - 4; i++) {
    if (
      data[i] === 0x0A &&
      data[i + 1] === 0x2D &&
      data[i + 2] === 0x2D &&
      data[i + 3] === 0x2D &&
      data[i + 4] === 0x0A
    ) {
      return i + 5; // offset after `\n---\n`
    }
  }

  // Check for `\n---` at EOF (no trailing newline)
  if (data.length >= 8) {
    const last4 = data.length - 4;
    if (
      data[last4] === 0x0A &&
      data[last4 + 1] === 0x2D &&
      data[last4 + 2] === 0x2D &&
      data[last4 + 3] === 0x2D
    ) {
      return data.length; // entire content is frontmatter
    }
  }

  return 0;
}

/**
 * Register the open hook for transparent decryption of suffix-matching notes.
 *
 * Hooks into `file-open` workspace events to detect when an encrypted
 * note is opened, then decrypts and presents the plaintext content to the editor.
 *
 * @param plugin - The Obsidian plugin instance (for event registration lifecycle)
 * @param cryptoEngine - The CryptoEngine for decryption
 * @param getSettings - Accessor for current plugin settings
 */
export function registerOpenHook(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.registerEvent(
    plugin.app.workspace.on('file-open', async (file: TFile | null) => {
      if (!file) return;

      const settings = getSettings();

      // Check if the file matches the encrypted note suffix
      if (!matchesEncryptedSuffix(file.name, settings.encryptedNoteSuffix)) return;

      try {
        await decryptFileOnOpen(plugin, file, cryptoEngine);
      } catch (error) {
        handleDecryptionFailure(plugin, file, error);
      }
    })
  );
}

/**
 * Decrypt a suffix-matching note on open.
 *
 * Flow:
 *   1. Read raw file bytes from vault
 *   2. Split into frontmatter (text) + body (binary)
 *   3. Check if body starts with MAGIC_BYTES → if not, it's plaintext, pass through
 *   4. Parse body bytes → EncryptedFileRecord
 *   5. Build EncryptionContext
 *   6. Call cryptoEngine.decrypt(record, context) → plaintext bytes
 *   7. Decode plaintext to UTF-8
 *   8. Present frontmatter + decrypted body to the editor
 */
async function decryptFileOnOpen(
  plugin: Plugin,
  file: TFile,
  cryptoEngine: CryptoEngine
): Promise<void> {
  // 1. Read raw file bytes from vault
  const rawBuffer = await plugin.app.vault.readBinary(file);
  const rawBytes = new Uint8Array(rawBuffer);

  // 2. Split into frontmatter and body at the byte level
  const frontmatterEndOffset = findFrontmatterEndOffset(rawBytes);
  const bodyBytes = rawBytes.slice(frontmatterEndOffset);

  // 3. Check if body starts with MAGIC_BYTES → if not, it's plaintext, pass through
  if (!isMagicMatch(bodyBytes)) return;

  // 4. Parse body bytes → EncryptedFileRecord
  const record = parse(bodyBytes);

  // 5. Build EncryptionContext
  const context: EncryptionContext = {
    vaultName: plugin.app.vault.getName(),
    filePath: file.path,
    formatVersion: FORMAT_VERSION,
  };

  // 6. Decrypt via CryptoEngine
  const plaintextBytes = await cryptoEngine.decrypt(record, context);

  // 7. Decode plaintext to UTF-8
  const plaintextBody = new TextDecoder().decode(plaintextBytes);

  // 8. Present frontmatter + decrypted body to the editor
  const frontmatterText = frontmatterEndOffset > 0
    ? new TextDecoder().decode(rawBytes.slice(0, frontmatterEndOffset))
    : null;

  const activeView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
  if (activeView && activeView.file?.path === file.path) {
    const fullContent = frontmatterText ? frontmatterText + plaintextBody : plaintextBody;
    const currentContent = activeView.editor.getValue();
    if (currentContent !== fullContent) {
      activeView.editor.setValue(fullContent);
    }
  }
}

/**
 * Handle decryption failure by showing an error notice and setting
 * the view to read-only (preview) mode.
 */
function handleDecryptionFailure(
  plugin: Plugin,
  file: TFile,
  error: unknown
): void {
  // Display error notice
  if (error instanceof PluginError) {
    showErrorNotice(error);
  } else {
    const message = error instanceof Error ? error.message : 'Unknown decryption error';
    showNotice(`Decryption failed for ${file.name}: ${message}`);
  }

  // Set the active view to read-only (preview) mode
  const activeView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
  if (activeView && activeView.file?.path === file.path) {
    const leaf = activeView.leaf;
    if (leaf) {
      const viewState = leaf.getViewState();
      leaf.setViewState({
        ...viewState,
        state: {
          ...viewState.state,
          mode: 'preview',
        },
      });
    }
  }
}
