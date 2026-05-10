import { Vault } from 'obsidian';
import { PluginError } from '../providers/errors';

/**
 * Writes binary content to a file in the vault.
 *
 * Uses vault.adapter.writeBinary() which overwrites the file in place.
 * This is safe in Obsidian's single-threaded environment.
 *
 * @param vault - Obsidian Vault instance providing file system access
 * @param path - Target file path (vault-relative)
 * @param newContent - The bytes to write
 * @throws PluginError with category 'crypto' on any failure
 */
export async function atomicFileWrite(
  vault: Vault,
  path: string,
  newContent: Uint8Array
): Promise<void> {
  try {
    await vault.adapter.writeBinary(path, newContent);
  } catch (err) {
    throw new PluginError(
      `Write failed for ${path}`,
      'crypto',
      undefined,
      undefined,
      path,
      err instanceof Error ? err : new Error(String(err))
    );
  }
}
