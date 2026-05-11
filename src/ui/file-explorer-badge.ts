/**
 * Adds a 🔒 badge to encrypted files in the file explorer.
 *
 * Scans vault for files with OCKE magic bytes and marks them
 * with a CSS class that shows a lock icon via ::after pseudo-element.
 */

import type { Plugin } from 'obsidian';

const ENCRYPTED_CLASS = 'ocke-encrypted-file';
const STYLE_ID = 'ocke-encrypted-badge-style';

/**
 * Set of file paths known to be encrypted.
 */
const encryptedPaths = new Set<string>();

/**
 * Install the file explorer badge system.
 * Returns a cleanup function.
 */
export function installFileExplorerBadge(
  plugin: Plugin,
  originalReadBinary: (path: string) => Promise<ArrayBuffer>
): () => void {
  // Inject CSS for the badge
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .nav-file.${ENCRYPTED_CLASS} .nav-file-title-content::after {
      content: ' 🔒';
      font-size: 0.8em;
      opacity: 0.7;
    }
  `;
  document.head.appendChild(style);

  // Scan vault on layout ready
  plugin.app.workspace.onLayoutReady(async () => {
    await scanVaultForEncryptedFiles(plugin, originalReadBinary);
    applyBadges(plugin);
  });

  // Re-apply badges when file explorer updates
  const interval = window.setInterval(() => {
    applyBadges(plugin);
  }, 3000);

  plugin.register(() => {
    window.clearInterval(interval);
  });

  // Return cleanup
  return () => {
    window.clearInterval(interval);
    const el = document.getElementById(STYLE_ID);
    if (el) el.remove();
    removeBadges();
  };
}

/**
 * Mark a file path as encrypted (call after encrypting).
 */
export function markFileEncrypted(filePath: string): void {
  encryptedPaths.add(filePath);
}

/**
 * Unmark a file path as encrypted (call after decrypting).
 */
export function markFileDecrypted(filePath: string): void {
  encryptedPaths.delete(filePath);
}

/**
 * Scan vault for encrypted binary files (check first 4 bytes for OCKE magic).
 */
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

/**
 * Apply CSS class to file explorer items for encrypted files.
 */
function applyBadges(_plugin: Plugin): void {
  const fileExplorer = document.querySelectorAll('.nav-file');

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

/**
 * Remove all badges.
 */
function removeBadges(): void {
  document.querySelectorAll(`.${ENCRYPTED_CLASS}`).forEach((el) => {
    el.classList.remove(ENCRYPTED_CLASS);
  });
}
