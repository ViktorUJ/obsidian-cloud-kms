import { describe, it, expect, vi, beforeEach } from 'vitest';
import { atomicFileWrite } from '../../../src/utils/atomic-write';
import { PluginError } from '../../../src/providers/errors';
import type { Vault } from 'obsidian';

function createMockVault(overrides: Partial<{
  writeBinary: (...args: any[]) => Promise<void>;
  rename: (...args: any[]) => Promise<void>;
  remove: (...args: any[]) => Promise<void>;
}> = {}): Vault {
  return {
    adapter: {
      writeBinary: overrides.writeBinary ?? vi.fn().mockResolvedValue(undefined),
      rename: overrides.rename ?? vi.fn().mockResolvedValue(undefined),
      remove: overrides.remove ?? vi.fn().mockResolvedValue(undefined),
    },
  } as unknown as Vault;
}

describe('atomicFileWrite', () => {
  const path = 'notes/secret.secret.md';
  const tempPath = `${path}.ocke-tmp`;
  const content = new Uint8Array([1, 2, 3, 4, 5]);

  it('writes to temp file then renames to target path', async () => {
    const writeBinary = vi.fn().mockResolvedValue(undefined);
    const rename = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, rename });

    await atomicFileWrite(vault, path, content);

    expect(writeBinary).toHaveBeenCalledWith(tempPath, content);
    expect(rename).toHaveBeenCalledWith(tempPath, path);
  });

  it('calls writeBinary before rename', async () => {
    const callOrder: string[] = [];
    const writeBinary = vi.fn().mockImplementation(async () => {
      callOrder.push('writeBinary');
    });
    const rename = vi.fn().mockImplementation(async () => {
      callOrder.push('rename');
    });
    const vault = createMockVault({ writeBinary, rename });

    await atomicFileWrite(vault, path, content);

    expect(callOrder).toEqual(['writeBinary', 'rename']);
  });

  it('throws PluginError with category crypto when writeBinary fails', async () => {
    const writeBinary = vi.fn().mockRejectedValue(new Error('disk full'));
    const remove = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, remove });

    await expect(atomicFileWrite(vault, path, content)).rejects.toThrow(PluginError);

    try {
      await atomicFileWrite(vault, path, content);
    } catch (err) {
      expect(err).toBeInstanceOf(PluginError);
      const pluginErr = err as PluginError;
      expect(pluginErr.category).toBe('crypto');
      expect(pluginErr.filePath).toBe(path);
      expect(pluginErr.message).toContain(path);
      expect(pluginErr.cause).toBeInstanceOf(Error);
      expect(pluginErr.cause!.message).toBe('disk full');
    }
  });

  it('throws PluginError with category crypto when rename fails', async () => {
    const writeBinary = vi.fn().mockResolvedValue(undefined);
    const rename = vi.fn().mockRejectedValue(new Error('permission denied'));
    const remove = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, rename, remove });

    await expect(atomicFileWrite(vault, path, content)).rejects.toThrow(PluginError);

    try {
      await atomicFileWrite(vault, path, content);
    } catch (err) {
      const pluginErr = err as PluginError;
      expect(pluginErr.category).toBe('crypto');
      expect(pluginErr.cause!.message).toBe('permission denied');
    }
  });

  it('removes temp file on writeBinary failure', async () => {
    const writeBinary = vi.fn().mockRejectedValue(new Error('disk full'));
    const remove = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, remove });

    await expect(atomicFileWrite(vault, path, content)).rejects.toThrow();

    expect(remove).toHaveBeenCalledWith(tempPath);
  });

  it('removes temp file on rename failure', async () => {
    const writeBinary = vi.fn().mockResolvedValue(undefined);
    const rename = vi.fn().mockRejectedValue(new Error('permission denied'));
    const remove = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, rename, remove });

    await expect(atomicFileWrite(vault, path, content)).rejects.toThrow();

    expect(remove).toHaveBeenCalledWith(tempPath);
  });

  it('still throws PluginError even if temp file cleanup fails', async () => {
    const writeBinary = vi.fn().mockRejectedValue(new Error('disk full'));
    const remove = vi.fn().mockRejectedValue(new Error('file not found'));
    const vault = createMockVault({ writeBinary, remove });

    await expect(atomicFileWrite(vault, path, content)).rejects.toThrow(PluginError);

    try {
      await atomicFileWrite(vault, path, content);
    } catch (err) {
      const pluginErr = err as PluginError;
      expect(pluginErr.category).toBe('crypto');
      expect(pluginErr.cause!.message).toBe('disk full');
    }
  });

  it('uses .ocke-tmp suffix for temp file path', async () => {
    const writeBinary = vi.fn().mockResolvedValue(undefined);
    const rename = vi.fn().mockResolvedValue(undefined);
    const vault = createMockVault({ writeBinary, rename });

    await atomicFileWrite(vault, 'folder/file.md', content);

    expect(writeBinary).toHaveBeenCalledWith('folder/file.md.ocke-tmp', content);
    expect(rename).toHaveBeenCalledWith('folder/file.md.ocke-tmp', 'folder/file.md');
  });
});
