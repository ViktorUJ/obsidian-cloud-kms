import { describe, it, expect, vi, beforeEach } from "vitest";
import type { PluginSettings } from "../../../src/types";

// Use dynamic import to avoid module resolution ordering issues
let CloudKmsSettingsTab: any;
let DEFAULT_SETTINGS: PluginSettings;
let loadSettings: any;
let SettingsPlugin: any;

beforeEach(async () => {
  const mod = await import("../../../src/ui/settings-tab");
  CloudKmsSettingsTab = mod.CloudKmsSettingsTab;
  DEFAULT_SETTINGS = mod.DEFAULT_SETTINGS;
  loadSettings = mod.loadSettings;
});

/**
 * Creates a mock plugin for testing settings.
 */
function createMockPlugin(initialSettings?: Partial<PluginSettings>) {
  const defaultSettings: PluginSettings = {
    awsCmkArn: "",
    encryptedNoteSuffix: ".secret.md",
    providers: [],
    vaultPolicies: [],
  };

  const settings: PluginSettings = {
    ...defaultSettings,
    ...initialSettings,
  };

  return {
    app: {} as any,
    settings,
    loadData: vi.fn().mockResolvedValue(settings),
    saveData: vi.fn().mockResolvedValue(undefined),
  };
}

describe("CloudKmsSettingsTab", () => {
  describe("constructor", () => {
    it("creates a settings tab instance", () => {
      const plugin = createMockPlugin();
      const tab = new CloudKmsSettingsTab(plugin.app, plugin);
      expect(tab).toBeDefined();
    });
  });

  describe("DEFAULT_SETTINGS", () => {
    it("has empty awsCmkArn", () => {
      expect(DEFAULT_SETTINGS.awsCmkArn).toBe("");
    });

    it("has default encrypted note suffix", () => {
      expect(DEFAULT_SETTINGS.encryptedNoteSuffix).toBe(".secret.md");
    });

    it("has empty providers array", () => {
      expect(DEFAULT_SETTINGS.providers).toEqual([]);
    });

    it("has empty vaultPolicies array", () => {
      expect(DEFAULT_SETTINGS.vaultPolicies).toEqual([]);
    });
  });
});

describe("loadSettings", () => {
  it("returns default settings when no data is stored", async () => {
    const plugin = createMockPlugin();
    (plugin.loadData as any).mockResolvedValue(null);

    const settings = await loadSettings(plugin);
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });

  it("merges stored data with defaults", async () => {
    const plugin = createMockPlugin();
    (plugin.loadData as any).mockResolvedValue({
      awsCmkArn: "arn:aws:kms:us-east-1:123456789012:key/test-key",
    });

    const settings = await loadSettings(plugin);
    expect(settings.awsCmkArn).toBe(
      "arn:aws:kms:us-east-1:123456789012:key/test-key"
    );
    expect(settings.encryptedNoteSuffix).toBe(".secret.md");
    expect(settings.providers).toEqual([]);
    expect(settings.vaultPolicies).toEqual([]);
  });

  it("preserves all stored fields", async () => {
    const stored: PluginSettings = {
      awsCmkArn: "arn:aws:kms:eu-west-1:999888777666:key/my-key",
      encryptedNoteSuffix: ".encrypted.md",
      autoDecryptBlocks: true,
      providers: [{ providerId: "aws-kms", enabled: true, cmkId: "test" }],
      vaultPolicies: [],
    };
    const plugin = createMockPlugin();
    (plugin.loadData as any).mockResolvedValue(stored);

    const settings = await loadSettings(plugin);
    expect(settings).toEqual(stored);
  });

  it("handles undefined loadData result", async () => {
    const plugin = createMockPlugin();
    (plugin.loadData as any).mockResolvedValue(undefined);

    const settings = await loadSettings(plugin);
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });
});
