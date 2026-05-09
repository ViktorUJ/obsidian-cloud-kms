/**
 * Plugin settings tab — multi-key configuration with aliases.
 */

import { App, PluginSettingTab, Setting } from "obsidian";
import type { PluginSettings, KeyConfig } from "../types";
import { validateAwsKmsArn } from "../utils/arn-validator";

/** Maximum length for the AWS KMS Key ARN field (characters). */
const ARN_MAX_LENGTH = 512;

/** Default plugin settings. */
export const DEFAULT_SETTINGS: PluginSettings = {
  awsCmkArn: "",
  keys: [],
  defaultKeyAlias: "",
  encryptedNoteSuffix: ".secret.md",
  autoDecryptBlocks: true,
  providers: [],
  vaultPolicies: [],
};

/**
 * Minimal interface for the plugin instance needed by settings.
 */
export interface SettingsPlugin {
  app: App;
  settings: PluginSettings;
  loadData(): Promise<unknown>;
  saveData(data: unknown): Promise<void>;
}

/**
 * Load settings from Obsidian's data store, merging with defaults.
 */
export async function loadSettings(
  plugin: SettingsPlugin
): Promise<PluginSettings> {
  const data = await plugin.loadData();
  return Object.assign({}, DEFAULT_SETTINGS, data ?? {});
}

/**
 * Cloud KMS Encryption plugin settings tab.
 */
export class CloudKmsSettingsTab extends PluginSettingTab {
  private plugin: SettingsPlugin;

  constructor(app: App, plugin: SettingsPlugin) {
    super(app, plugin as any);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "Cloud KMS Encryption Settings" });

    // --- Keys section ---
    containerEl.createEl("h3", { text: "Encryption Keys" });
    containerEl.createEl("p", {
      text: "Add KMS keys with aliases. Use aliases in %%secret-start:alias%% markers. The default key is used when no alias is specified.",
      cls: "setting-item-description",
    });

    this.addKeysSection(containerEl);

    // --- Default key ---
    this.addDefaultKeySetting(containerEl);

    // --- Legacy single key (backward compat) ---
    containerEl.createEl("h3", { text: "Legacy Settings" });
    containerEl.createEl("p", {
      text: "Used as fallback if no keys are configured above.",
      cls: "setting-item-description",
    });
    this.addArnSetting(containerEl);

    // --- Behavior ---
    containerEl.createEl("h3", { text: "Behavior" });
    this.addAutoDecryptBlocksSetting(containerEl);
  }

  private addKeysSection(containerEl: HTMLElement): void {
    const keys = this.plugin.settings.keys;

    // Render existing keys
    for (let i = 0; i < keys.length; i++) {
      this.addKeyRow(containerEl, keys[i], i);
    }

    // Add button
    new Setting(containerEl)
      .addButton((btn) => {
        btn.setButtonText("+ Add Key").onClick(async () => {
          this.plugin.settings.keys.push({ alias: "", arn: "" });
          await this.plugin.saveData(this.plugin.settings);
          this.display(); // Re-render
        });
      });
  }

  private addKeyRow(containerEl: HTMLElement, key: KeyConfig, index: number): void {
    const setting = new Setting(containerEl)
      .setName(`Key ${index + 1}`)
      .addText((text) => {
        text
          .setPlaceholder("alias (e.g. finance)")
          .setValue(key.alias)
          .onChange(async (value: string) => {
            this.plugin.settings.keys[index].alias = value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
            await this.plugin.saveData(this.plugin.settings);
          });
        text.inputEl.style.width = "120px";
      })
      .addText((text) => {
        text
          .setPlaceholder("arn:aws:kms:region:account:key/id")
          .setValue(key.arn)
          .onChange(async (value: string) => {
            this.plugin.settings.keys[index].arn = value.slice(0, ARN_MAX_LENGTH);
            await this.plugin.saveData(this.plugin.settings);
          });
        text.inputEl.style.width = "300px";
      })
      .addButton((btn) => {
        btn.setButtonText("✕").setWarning().onClick(async () => {
          this.plugin.settings.keys.splice(index, 1);
          // Clear defaultKeyAlias if it was pointing to removed key
          if (this.plugin.settings.defaultKeyAlias === key.alias) {
            this.plugin.settings.defaultKeyAlias = "";
          }
          await this.plugin.saveData(this.plugin.settings);
          this.display(); // Re-render
        });
      });

    // Validation
    if (key.arn && !validateAwsKmsArn(key.arn).valid) {
      const errorEl = setting.controlEl.createEl("div", {
        text: "Invalid ARN format",
        cls: "setting-error-message",
      });
      errorEl.style.color = "var(--text-error)";
      errorEl.style.fontSize = "0.8em";
    }
  }

  private addDefaultKeySetting(containerEl: HTMLElement): void {
    const keys = this.plugin.settings.keys;
    const aliases = keys.filter(k => k.alias).map(k => k.alias);

    new Setting(containerEl)
      .setName("Default key")
      .setDesc("Used when %%secret-start%% has no alias specified")
      .addDropdown((dropdown) => {
        dropdown.addOption("", "(none)");
        for (const alias of aliases) {
          dropdown.addOption(alias, alias);
        }
        dropdown.setValue(this.plugin.settings.defaultKeyAlias);
        dropdown.onChange(async (value: string) => {
          this.plugin.settings.defaultKeyAlias = value;
          await this.plugin.saveData(this.plugin.settings);
        });
      });
  }

  private addArnSetting(containerEl: HTMLElement): void {
    let errorEl: HTMLElement | null = null;

    const setting = new Setting(containerEl)
      .setName("AWS KMS Key ARN (legacy)")
      .setDesc("Fallback key if no keys configured above")
      .addText((text) => {
        text
          .setPlaceholder("arn:aws:kms:us-east-1:123456789012:key/...")
          .setValue(this.plugin.settings.awsCmkArn)
          .onChange(async (value: string) => {
            const clamped = value.slice(0, ARN_MAX_LENGTH);
            if (errorEl) { errorEl.remove(); errorEl = null; }

            const stripped = clamped.trim();
            if (stripped.length > 0 && !validateAwsKmsArn(stripped).valid) {
              errorEl = setting.controlEl.createEl("div", {
                text: "Invalid AWS KMS key ARN format",
                cls: "setting-error-message",
              });
              errorEl.style.color = "var(--text-error)";
              errorEl.style.fontSize = "0.85em";
              errorEl.style.marginTop = "4px";
            }

            this.plugin.settings.awsCmkArn = clamped;
            await this.plugin.saveData(this.plugin.settings);
          });
        text.inputEl.maxLength = ARN_MAX_LENGTH;
        text.inputEl.style.width = "100%";
      });
  }

  private addAutoDecryptBlocksSetting(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName("Auto-decrypt on read")
      .setDesc("Automatically decrypt encrypted blocks when opening files")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.autoDecryptBlocks)
          .onChange(async (value: boolean) => {
            this.plugin.settings.autoDecryptBlocks = value;
            await this.plugin.saveData(this.plugin.settings);
          });
      });
  }
}
