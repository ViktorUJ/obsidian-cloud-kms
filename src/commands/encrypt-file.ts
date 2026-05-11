/**
 * Command: "Encrypt current file with AWS KMS"
 *
 * Encrypts the currently active binary file (pdf, png, mp3, etc.) in place.
 * The file name does NOT change. The content is replaced with OCKE binary format.
 *
 * For .md files — use %%secret-start%% / %%secret-end%% blocks instead.
 *
 * The readBinary() adapter patch will transparently decrypt on read,
 * so Obsidian can preview the file as usual.
 *
 * Flow:
 *   1. Get active file → if none or .md, show notice
 *   2. Check if already encrypted (OCKE magic bytes) → skip
 *   3. Read binary content
 *   4. Encrypt via CryptoEngine
 *   5. Serialize to OCKE binary format
 *   6. Write back to same path
 */

import { Notice, Plugin } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION, KMS_FILE_TIMEOUT_MS, NOTICE_DURATION_MS } from '../constants';
import { validateAwsKmsArn } from '../utils/arn-validator';
import { serialize } from '../format/serializer';
import { isMagicMatch } from '../format/parser';
import { markFileEncrypted } from '../ui/file-explorer-badge';

export function registerEncryptFileCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): void {
  plugin.addCommand({
    id: 'encrypt-current-file-aws-kms',
    name: 'Encrypt current file with AWS KMS',
    callback: () => {
      executeEncryptFile(plugin, cryptoEngine, getSettings).catch(() => {});
    },
  });
}

async function executeEncryptFile(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings
): Promise<void> {
  const file = plugin.app.workspace.getActiveFile();
  if (!file) {
    new Notice('No active file', NOTICE_DURATION_MS);
    return;
  }

  // For .md files, suggest using secret blocks instead
  if (file.extension === 'md') {
    new Notice(
      'For markdown files, use %%secret-start%% / %%secret-end%% blocks.\nThis command is for binary files (PDF, images, etc.).',
      NOTICE_DURATION_MS
    );
    return;
  }

  const settings = getSettings();
  const arnValidation = validateAwsKmsArn(settings.awsCmkArn);
  if (!arnValidation.valid) {
    new Notice('Configure a valid AWS KMS Key ARN in plugin settings.', NOTICE_DURATION_MS);
    return;
  }

  try {
    // Read binary content
    const contentBuffer = await plugin.app.vault.readBinary(file);
    const contentBytes = new Uint8Array(contentBuffer);

    // Check if already encrypted (OCKE magic bytes)
    if (isMagicMatch(contentBytes)) {
      new Notice('File is already encrypted', NOTICE_DURATION_MS);
      return;
    }

    // Build encryption context
    const context: EncryptionContext = {
      vaultName: plugin.app.vault.getName(),
      filePath: file.path,
      formatVersion: FORMAT_VERSION,
    };

    // Encrypt
    const record = await withTimeout(
      cryptoEngine.encrypt(contentBytes, settings.awsCmkArn, 'aws-kms', context),
      KMS_FILE_TIMEOUT_MS
    );

    // Serialize to OCKE binary format
    const encryptedBinary = serialize(record);

    // Write back to same path (no rename)
    await plugin.app.vault.adapter.writeBinary(file.path, encryptedBinary);

    markFileEncrypted(file.path);
    new Notice(`Encrypted: ${file.name}`, NOTICE_DURATION_MS);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'File encryption failed';
    new Notice(`Encryption error: ${message}`, NOTICE_DURATION_MS);
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`KMS operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}
