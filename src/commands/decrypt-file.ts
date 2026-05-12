/**
 * Command: "Decrypt current file with AWS KMS"
 *
 * Permanently decrypts a binary file — replaces OCKE encrypted content
 * with the original plaintext bytes on disk.
 *
 * After this, the file is no longer encrypted.
 */

import { Notice, Plugin } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION, KMS_FILE_TIMEOUT_MS, NOTICE_DURATION_MS } from '../constants';
import { isMagicMatch, parse } from '../format/parser';
import { markFileDecrypted } from '../ui/file-explorer-badge';

export function registerDecryptFileCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings,
  getOriginalReadBinary: () => ((path: string) => Promise<ArrayBuffer>) | undefined
): void {
  plugin.addCommand({
    id: 'decrypt-current-file-aws-kms',
    name: 'Decrypt current file with AWS KMS (permanent)',
    callback: () => {
      executeDecryptFile(plugin, cryptoEngine, getSettings, getOriginalReadBinary).catch(() => {});
    },
  });
}

async function executeDecryptFile(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  _getSettings: () => PluginSettings,
  getOriginalReadBinary: () => ((path: string) => Promise<ArrayBuffer>) | undefined
): Promise<void> {
  const file = plugin.app.workspace.getActiveFile();
  if (!file) {
    new Notice('No active file', NOTICE_DURATION_MS);
    return;
  }

  if (file.extension === 'md') {
    new Notice('For markdown files, use "Unwrap secret block" command.', NOTICE_DURATION_MS);
    return;
  }

  try {
    // Read raw binary bypassing our decrypt patch
    const originalRead = getOriginalReadBinary();
    if (!originalRead) {
      new Notice('Plugin not fully initialized', NOTICE_DURATION_MS);
      return;
    }

    const contentBuffer = await originalRead(file.path);
    const contentBytes = new Uint8Array(contentBuffer);

    // Check if actually encrypted
    if (!isMagicMatch(contentBytes)) {
      new Notice('File is not encrypted', NOTICE_DURATION_MS);
      return;
    }

    // Parse and decrypt
    const record = parse(contentBytes);
    const context: EncryptionContext = {
      vaultName: plugin.app.vault.getName(),
      filePath: file.path,
      formatVersion: FORMAT_VERSION,
    };

    const plaintextBytes = await withTimeout(
      cryptoEngine.decrypt(record, context),
      KMS_FILE_TIMEOUT_MS
    );

    // Write decrypted content back
    await plugin.app.vault.adapter.writeBinary(file.path, plaintextBytes);

    markFileDecrypted(file.path);
    new Notice(`Decrypted: ${file.name}`, NOTICE_DURATION_MS);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'File decryption failed';
    new Notice(`Decryption error: ${message}`, NOTICE_DURATION_MS);
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      reject(new Error(`KMS operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise.then(
      (value) => { window.clearTimeout(timer); resolve(value); },
      (err) => { window.clearTimeout(timer); reject(err); }
    );
  });
}
