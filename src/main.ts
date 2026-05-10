/**
 * Plugin main entry point — CloudKmsPlugin extends Obsidian Plugin.
 *
 * Uses monkey-patching of vault.adapter.read/write for transparent encryption:
 * - adapter.read(): decrypts ```ocke-v1 → ```secret (editor sees plaintext)
 * - adapter.write(): encrypts ```secret → ```ocke-v1 (disk has ciphertext)
 */

import { Plugin } from 'obsidian';
import { PluginSettings } from './types';
import { BufferRegistry } from './core/buffer-registry';
import { ProviderDispatcherImpl } from './providers/dispatcher';
import { AwsKmsAdapter } from './providers/aws-kms-adapter';
import { CryptoEngineImpl } from './core/crypto-engine';
import { CloudKmsSettingsTab, DEFAULT_SETTINGS, loadSettings } from './ui/settings-tab';
import { registerEncryptSelectionCommand } from './commands/encrypt-selection';
import { registerDecryptSelectionCommand } from './commands/decrypt-selection';
import { registerAttachmentHook } from './hooks/attachment-hook';
import { registerEncryptFileCommand } from './commands/encrypt-file';
import { registerEncryptedFileView } from './ui/encrypted-view';
import { installCryptoAdapterPatch } from './hooks/crypto-adapter-patch';

export default class CloudKmsPlugin extends Plugin {
  settings: PluginSettings = DEFAULT_SETTINGS;

  private bufferRegistry!: BufferRegistry;
  private cryptoEngine!: CryptoEngineImpl;
  private uninstallAdapterPatch?: () => void;

  async onload(): Promise<void> {
    // 1. Load settings
    await this.loadSettings();

    // 2. Create BufferRegistry
    this.bufferRegistry = new BufferRegistry();

    // 3. Create ProviderDispatcher and register AWS adapter
    const dispatcher = new ProviderDispatcherImpl();
    dispatcher.register(new AwsKmsAdapter());

    // 4. Create CryptoEngine
    this.cryptoEngine = new CryptoEngineImpl(dispatcher);

    // 5. Register settings tab
    this.addSettingTab(new CloudKmsSettingsTab(this.app, this));

    // 6. Register commands
    registerEncryptSelectionCommand(this, this.cryptoEngine, () => this.settings);
    registerDecryptSelectionCommand(this, this.cryptoEngine, () => this.settings);
    registerEncryptFileCommand(this, this.cryptoEngine, () => this.settings);

    // 7. Install crypto adapter patch (transparent encrypt/decrypt)
    this.uninstallAdapterPatch = installCryptoAdapterPatch(
      this,
      this.cryptoEngine,
      () => this.settings
    );

    // 8. Register attachment hook
    registerAttachmentHook(this, this.cryptoEngine, () => this.settings, this.bufferRegistry);

    // 9. Register encrypted file view (fallback for errors)
    registerEncryptedFileView(this);
  }

  async onunload(): Promise<void> {
    // Restore original adapter methods
    if (this.uninstallAdapterPatch) {
      this.uninstallAdapterPatch();
    }

    // Zero all in-memory buffers
    this.bufferRegistry.releaseAll();
  }

  async loadSettings(): Promise<void> {
    this.settings = await loadSettings(this);
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }
}
