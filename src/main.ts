/**
 * Plugin main entry point — CloudKmsPlugin extends Obsidian Plugin.
 *
 * onload():
 *   1. Load settings via loadData()
 *   2. Create BufferRegistry
 *   3. Create ProviderDispatcherImpl, register AwsKmsAdapter
 *   4. Create CryptoEngineImpl(dispatcher)
 *   5. Register settings tab (CloudKmsSettingsTab)
 *   6. Register Phase 1 commands (encrypt/decrypt selection)
 *   7. Register Phase 2 hooks (save, open, attachment)
 *   8. Register Phase 2 commands (encrypt file)
 *   9. Register Phase 2 views (encrypted file view)
 *
 * onunload():
 *   1. bufferRegistry.releaseAll() — zero all in-memory buffers
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
import { registerSaveHook } from './hooks/save-hook';
import { registerOpenHook } from './hooks/open-hook';
import { registerAttachmentHook } from './hooks/attachment-hook';
import { registerInlineBlockSaveHook, registerInlineBlockOpenHook } from './hooks/inline-block-hook';
import { registerEncryptFileCommand } from './commands/encrypt-file';
import { registerEncryptedFileView } from './ui/encrypted-view';

export default class CloudKmsPlugin extends Plugin {
  settings: PluginSettings = DEFAULT_SETTINGS;

  private bufferRegistry!: BufferRegistry;
  private cryptoEngine!: CryptoEngineImpl;

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

    // 6. Register Phase 1 commands
    registerEncryptSelectionCommand(
      this,
      this.cryptoEngine,
      () => this.settings
    );

    registerDecryptSelectionCommand(
      this,
      this.cryptoEngine,
      () => this.settings
    );

    // 7. Register Phase 2 hooks
    registerSaveHook(this, this.cryptoEngine, () => this.settings);
    registerOpenHook(this, this.cryptoEngine, () => this.settings);
    registerAttachmentHook(this, this.cryptoEngine, () => this.settings, this.bufferRegistry);
    registerInlineBlockSaveHook(this, this.cryptoEngine, () => this.settings);
    registerInlineBlockOpenHook(this, this.cryptoEngine, () => this.settings);

    // 8. Register Phase 2 commands
    registerEncryptFileCommand(this, this.cryptoEngine, () => this.settings);

    // 9. Register Phase 2 views
    registerEncryptedFileView(this);
  }

  async onunload(): Promise<void> {
    // Force-release all SecureBuffers to zero in-memory plaintext/DEK material
    this.bufferRegistry.releaseAll();
  }

  async loadSettings(): Promise<void> {
    this.settings = await loadSettings(this);
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }
}
