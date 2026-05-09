/**
 * Command: "Encrypt current file with AWS KMS"
 *
 * Encrypts the currently active binary file (pdf, png, mp3, etc.) in place.
 * If multiple keys are configured, shows a picker to choose which key to use.
 * The file name does NOT change. The content is replaced with OCKE binary format.
 */

import { Notice, Plugin, FuzzySuggestModal } from 'obsidian';
import type { CryptoEngine, EncryptionContext, PluginSettings } from '../types';
import { FORMAT_VERSION, KMS_FILE_TIMEOUT_MS, NOTICE_DURATION_MS } from '../constants';
import { serialize } from '../format/serializer';
import { isMagicMatch } from '../format/parser';
import { markFileEncrypted } from '../ui/file-explorer-badge';
import { getKeyAliases, resolveKeyArn } from '../utils/key-resolver';

export function registerEncryptFileCommand(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings,
  getOriginalReadBinary: () => ((path: string) => Promise<ArrayBuffer>) | undefined
): void {
  plugin.addCommand({
    id: 'encrypt-current-file-aws-kms',
    name: 'Encrypt current file with AWS KMS',
    callback: () => {
      executeEncryptFile(plugin, cryptoEngine, getSettings, getOriginalReadBinary).catch(() => {});
    },
  });
}

async function executeEncryptFile(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getSettings: () => PluginSettings,
  getOriginalReadBinary: () => ((path: string) => Promise<ArrayBuffer>) | undefined
): Promise<void> {
  const file = plugin.app.workspace.getActiveFile();
  if (!file) {
    new Notice('No active file', NOTICE_DURATION_MS);
    return;
  }

  if (file.extension === 'md') {
    new Notice(
      'For markdown files, use %%secret-start%% / %%secret-end%% blocks.\nThis command is for binary files (PDF, images, etc.).',
      NOTICE_DURATION_MS
    );
    return;
  }

  // Read raw binary bypassing our decrypt patch
  const originalRead = getOriginalReadBinary();
  if (!originalRead) {
    new Notice('Plugin not fully initialized', NOTICE_DURATION_MS);
    return;
  }

  const contentBuffer = await originalRead(file.path);
  const contentBytes = new Uint8Array(contentBuffer);

  if (isMagicMatch(contentBytes)) {
    new Notice('File is already encrypted', NOTICE_DURATION_MS);
    return;
  }

  const settings = getSettings();
  const aliases = getKeyAliases(settings);

  if (aliases.length === 0) {
    new Notice('Configure at least one AWS KMS Key in plugin settings.', NOTICE_DURATION_MS);
    return;
  }

  if (aliases.length === 1) {
    // Single key — encrypt directly
    const arn = resolveKeyArn(aliases[0] === 'default' ? undefined : aliases[0], settings);
    if (!arn) {
      new Notice('No valid key ARN configured.', NOTICE_DURATION_MS);
      return;
    }
    await doEncrypt(plugin, cryptoEngine, file.path, contentBytes, arn);
  } else {
    // Multiple keys — show picker
    new KeyPickerModal(plugin.app, aliases, async (chosen) => {
      const arn = resolveKeyArn(chosen, settings);
      if (!arn) {
        new Notice(`Key "${chosen}" has no valid ARN.`, NOTICE_DURATION_MS);
        return;
      }
      await doEncrypt(plugin, cryptoEngine, file.path, contentBytes, arn);
    }).open();
  }
}

async function doEncrypt(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  filePath: string,
  contentBytes: Uint8Array,
  cmkArn: string
): Promise<void> {
  try {
    const context: EncryptionContext = {
      vaultName: plugin.app.vault.getName(),
      filePath,
      formatVersion: FORMAT_VERSION,
    };

    const record = await withTimeout(
      cryptoEngine.encrypt(contentBytes, cmkArn, 'aws-kms', context),
      KMS_FILE_TIMEOUT_MS
    );

    const encryptedBinary = serialize(record);
    await plugin.app.vault.adapter.writeBinary(filePath, encryptedBinary);

    markFileEncrypted(filePath);
    const fileName = filePath.split('/').pop() ?? filePath;
    new Notice(`Encrypted: ${fileName}`, NOTICE_DURATION_MS);
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

class KeyPickerModal extends FuzzySuggestModal<string> {
  private readonly aliases: string[];
  private readonly onChoose: (alias: string) => void;

  constructor(app: any, aliases: string[], onChoose: (alias: string) => void) {
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
