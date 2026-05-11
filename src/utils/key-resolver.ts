/**
 * Key resolver — resolves alias to ARN for encryption.
 *
 * Resolution order:
 * 1. If alias provided → look up in settings.keys[]
 * 2. If no alias → use settings.defaultKeyAlias → look up in settings.keys[]
 * 3. Fallback → settings.awsCmkArn (backward compat)
 *
 * For decryption: ARN is already stored in the encrypted data (cmkId field).
 * No resolution needed — just call KMS Decrypt with that ARN.
 */

import type { PluginSettings } from '../types';

/**
 * Resolve a key alias to an ARN for encryption.
 *
 * @param alias - Optional alias from the secret block marker (e.g., "finance")
 * @param settings - Current plugin settings
 * @returns The ARN to use, or null if no valid key found
 */
export function resolveKeyArn(alias: string | undefined, settings: PluginSettings): string | null {
  // If alias specified, look it up
  if (alias) {
    const key = settings.keys.find(k => k.alias === alias);
    if (key && key.arn) return key.arn;
    return null; // Alias specified but not found
  }

  // Try default key alias
  if (settings.defaultKeyAlias) {
    const key = settings.keys.find(k => k.alias === settings.defaultKeyAlias);
    if (key && key.arn) return key.arn;
  }

  // Fallback to legacy single-key setting
  if (settings.awsCmkArn && settings.awsCmkArn.trim()) {
    return settings.awsCmkArn;
  }

  return null;
}

/**
 * Get all configured key aliases for UI selection.
 */
export function getKeyAliases(settings: PluginSettings): string[] {
  const aliases: string[] = [];

  for (const key of settings.keys) {
    if (key.alias && key.arn) {
      aliases.push(key.alias);
    }
  }

  // If legacy key is set but no keys[] configured, add a "default" entry
  if (aliases.length === 0 && settings.awsCmkArn) {
    aliases.push('default');
  }

  return aliases;
}
