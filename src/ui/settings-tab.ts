/**
 * Plugin settings tab — exposes configuration fields with inline validation.
 *
 * Phase 1: "AWS KMS Key ARN" text input with ARN format validation.
 * Phase 2: "Encrypted note suffix" text input (1–64 chars).
 *
 * Persists settings via Obsidian loadData/saveData.
 */

import { App, PluginSettingTab, Setting } from "obsidian";
import type { PluginSettings } from "../types";
import { validateAwsKmsArn } from "../utils/arn-validator";
import {
  ENCRYPTED_NOTE_SUFFIX_DEFAULT,
  ENCRYPTED_NOTE_SUFFIX_MAX_LEN,
} from "../constants";

/** Maximum length for the AWS KMS Key ARN field (characters). */
const ARN_MAX_LENGTH = 512;

/** Default plugin settings. */
export const DEFAULT_SETTINGS: PluginSettings = {
  awsCmkArn: "",
  encryptedNoteSuffix: ENCRYPTED_NOTE_SUFFIX_DEFAULT,
  autoDecryptBlocks: true,
  providers: [],
  vaultPolicies: [],
};

/**
 * Minimal interface for the plugin instance needed by settings.
 * Allows testing without a full Plugin dependency.
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
 *
 * Provides:
 * - "AWS KMS Key ARN" text input with inline validation (Phase 1)
 * - "Encrypted note suffix" text input with length validation (Phase 2)
 *
 * Validates ARN format on change and displays inline error for invalid values.
 * Empty/whitespace ARN shows no error but commands remain disabled.
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

    // Phase 1 — AWS KMS
    containerEl.createEl("h3", { text: "Phase 1 — AWS KMS" });
    this.addArnSetting(containerEl);

    // Phase 2 — Transparent Encryption
    containerEl.createEl("h3", { text: "Phase 2 — Transparent Encryption" });
    this.addSuffixSetting(containerEl);
    this.addAutoDecryptBlocksSetting(containerEl);
  }

  /**
   * Adds the "AWS KMS Key ARN" setting with inline validation.
   *
   * Behavior:
   * - Empty/whitespace: no error shown, commands disabled
   * - Invalid format: red error text "Invalid AWS KMS key ARN format"
   * - Valid: no error, commands enabled
   * - Max 512 characters
   */
  private addArnSetting(containerEl: HTMLElement): void {
    let errorEl: HTMLElement | null = null;

    const setting = new Setting(containerEl)
      .setName("AWS KMS Key ARN")
      .setDesc(
        "The ARN of the AWS KMS key used for envelope encryption. " +
          "Format: arn:aws:kms:{region}:{account-id}:key/{key-id}"
      )
      .addText((text) => {
        text
          .setPlaceholder("arn:aws:kms:us-east-1:123456789012:key/...")
          .setValue(this.plugin.settings.awsCmkArn)
          .onChange(async (value: string) => {
            // Enforce max length
            const clampedValue = value.slice(0, ARN_MAX_LENGTH);

            // Remove previous error
            if (errorEl) {
              errorEl.remove();
              errorEl = null;
            }

            const stripped = clampedValue.trim();
            if (stripped.length === 0) {
              // Empty/whitespace: no error shown, commands will be disabled
              this.plugin.settings.awsCmkArn = "";
              await this.plugin.saveData(this.plugin.settings);
              return;
            }

            // Validate ARN format
            const result = validateAwsKmsArn(stripped);
            if (!result.valid) {
              // Show inline red error
              errorEl = setting.controlEl.createEl("div", {
                text: "Invalid AWS KMS key ARN format",
                cls: "setting-error-message",
              });
              errorEl.style.color = "var(--text-error)";
              errorEl.style.fontSize = "0.85em";
              errorEl.style.marginTop = "4px";
            }

            // Persist the value (user may be mid-typing a valid ARN)
            this.plugin.settings.awsCmkArn = clampedValue;
            await this.plugin.saveData(this.plugin.settings);
          });

        // Enforce max length on the input element
        text.inputEl.maxLength = ARN_MAX_LENGTH;
        text.inputEl.style.width = "100%";
      });

    // Show existing validation error on initial display if ARN is invalid
    const currentArn = this.plugin.settings.awsCmkArn.trim();
    if (currentArn.length > 0) {
      const result = validateAwsKmsArn(currentArn);
      if (!result.valid) {
        errorEl = setting.controlEl.createEl("div", {
          text: "Invalid AWS KMS key ARN format",
          cls: "setting-error-message",
        });
        errorEl.style.color = "var(--text-error)";
        errorEl.style.fontSize = "0.85em";
        errorEl.style.marginTop = "4px";
      }
    }
  }

  /**
   * Adds the "Encrypted note suffix" setting with length validation.
   *
   * Behavior:
   * - Must be 1–64 characters
   * - Default: ".secret.md"
   * - Empty or >64 chars: show error, reject change
   */
  private addSuffixSetting(containerEl: HTMLElement): void {
    let errorEl: HTMLElement | null = null;

    const setting = new Setting(containerEl)
      .setName("Encrypted note suffix")
      .setDesc(
        "Notes with file names ending in this suffix will be automatically " +
          `encrypted on save. Default: ${ENCRYPTED_NOTE_SUFFIX_DEFAULT}`
      )
      .addText((text) => {
        text
          .setPlaceholder(ENCRYPTED_NOTE_SUFFIX_DEFAULT)
          .setValue(this.plugin.settings.encryptedNoteSuffix)
          .onChange(async (value: string) => {
            // Remove previous error
            if (errorEl) {
              errorEl.remove();
              errorEl = null;
            }

            // Validate: non-empty, 1–64 chars
            if (
              value.length === 0 ||
              value.length > ENCRYPTED_NOTE_SUFFIX_MAX_LEN
            ) {
              errorEl = setting.controlEl.createEl("div", {
                text: `Suffix must be between 1 and ${ENCRYPTED_NOTE_SUFFIX_MAX_LEN} characters`,
                cls: "setting-error-message",
              });
              errorEl.style.color = "var(--text-error)";
              errorEl.style.fontSize = "0.85em";
              errorEl.style.marginTop = "4px";
              // Don't persist invalid value
              return;
            }

            this.plugin.settings.encryptedNoteSuffix = value;
            await this.plugin.saveData(this.plugin.settings);
          });

        text.inputEl.maxLength = ENCRYPTED_NOTE_SUFFIX_MAX_LEN;
      });

    // Show existing validation error on initial display
    const currentSuffix = this.plugin.settings.encryptedNoteSuffix;
    if (
      currentSuffix.length === 0 ||
      currentSuffix.length > ENCRYPTED_NOTE_SUFFIX_MAX_LEN
    ) {
      errorEl = setting.controlEl.createEl("div", {
        text: `Suffix must be between 1 and ${ENCRYPTED_NOTE_SUFFIX_MAX_LEN} characters`,
        cls: "setting-error-message",
      });
      errorEl.style.color = "var(--text-error)";
      errorEl.style.fontSize = "0.85em";
      errorEl.style.marginTop = "4px";
    }
  }

  /**
   * Adds the "Auto-decrypt encrypted blocks on open" toggle setting.
   *
   * Behavior:
   * - Default: true (enabled)
   * - When enabled: encrypted blocks are automatically decrypted when opening a note
   * - When disabled: use 'Decrypt selection' command manually
   */
  private addAutoDecryptBlocksSetting(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName("Auto-decrypt encrypted blocks on open")
      .setDesc(
        "When enabled, encrypted blocks are automatically decrypted when opening a note. " +
          "When disabled, use 'Decrypt selection' command manually."
      )
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
