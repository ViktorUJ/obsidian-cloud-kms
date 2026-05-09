import { Vault } from 'obsidian';
import { PluginError } from '../providers/errors';

/**
 * Atomically writes content to a file using a temp-file-then-rename strategy.
 *
 * Writes to `${path}.ocke-tmp` first, then renames to the target path.
 * On any failure, removes the temp file (best effort) and throws a PluginError.
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
  const tempPath = `${path}.ocke-tmp`;

  try {
    await vault.adapter.writeBinary(tempPath, newContent);
    await vault.adapter.rename(tempPath, path);
  } catch (err) {
    // Best-effort cleanup of temp file
    try {
      await vault.adapter.remove(tempPath);
    } catch {
      // Ignore cleanup errors
    }

    throw new PluginError(
      `Atomic write failed for ${path}`,
      'crypto',
      undefined,
      undefined,
      path,
      err instanceof Error ? err : new Error(String(err))
    );
  }
}
