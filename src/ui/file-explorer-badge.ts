/**
 * Adds a 🔒 badge to encrypted files in the file explorer.
 * CSS is in styles.css (class: ocke-encrypted-file).
 */

import type { Plugin } from 'obsidian';

const ENCRYPTED_CLASS = 'ocke-encrypted-file';
const encryptedPaths = new Set<string>();

export function installFileExplorerBadge(
  plugin: Plugin,
  originalReadBinary: (path: string) => Promise<ArrayBuffer>
): () => void {
  // Scan vault on layout ready
  plugin.app.workspace.onLayoutReady(async () => {
    await scanVaultForEncryptedFiles(plugin, originalReadBinary);
    applyBadges();
  });

  // Re-apply badges when file explorer updates (on file-open events)
  plugin.registerEvent(
    plugin.app.workspace.on('file-open', () => {
      applyBadges();
    })
  );

  return () => {
    removeBadges();
  };
}

export function markFileEncrypted(filePath: string): void {
  encryptedPaths.add(filePath);
}

export function markFileDecrypted(filePath: string): void {
  encryptedPaths.delete(filePath);
}

async function scanVaultForEncryptedFiles(
  plugin: Plugin,
  originalReadBinary: (path: string) => Promise<ArrayBuffer>
): Promise<void> {
  const files = plugin.app.vault.getFiles();
  for (const file of files) {
    if (file.path.endsWith('.md')) continue;
    try {
      const data = await originalReadBinary(file.path);
      const bytes = new Uint8Array(data, 0, Math.min(4, data.byteLength));
      if (bytes.length >= 4 && bytes[0] === 0x4F && bytes[1] === 0x43 && bytes[2] === 0x4B && bytes[3] === 0x45) {
        encryptedPaths.add(file.path);
      }
    } catch {
      // Skip unreadable files
    }
  }
}

function applyBadges(): void {
  const fileExplorer = activeDocument.querySelectorAll('.nav-file');
  fileExplorer.forEach((el) => {
    const titleEl = el.querySelector('.nav-file-title');
    if (!titleEl) return;
    const path = titleEl.getAttribute('data-path');
    if (!path) return;
    if (encryptedPaths.has(path)) {
      el.classList.add(ENCRYPTED_CLASS);
    } else {
      el.classList.remove(ENCRYPTED_CLASS);
    }
  });
}

function removeBadges(): void {
  activeDocument.querySelectorAll(`.${ENCRYPTED_CLASS}`).forEach((el) => {
    el.classList.remove(ENCRYPTED_CLASS);
  });
}
