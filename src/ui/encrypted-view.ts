/**
 * Read-only view for encrypted files when decryption fails.
 *
 * Displays:
 * 1. Error banner (red background) with the failure message
 * 2. Raw on-disk content as base64 for inspection
 * 3. No editing capabilities (read-only)
 *
 * Used by the open hook when KMS is unavailable, credentials are missing,
 * or ciphertext integrity verification fails.
 */

import { ItemView, Plugin, WorkspaceLeaf } from 'obsidian';

/** Unique view type identifier for the encrypted file read-only view. */
export const ENCRYPTED_FILE_VIEW_TYPE = 'encrypted-file-view';

/** Alias for backward compatibility with open-hook. */
export const ENCRYPTED_VIEW_TYPE = ENCRYPTED_FILE_VIEW_TYPE;

/**
 * State stored in the leaf for restoring the view on workspace reload.
 */
interface EncryptedFileViewState extends Record<string, unknown> {
  filePath: string;
  errorMessage: string;
  rawContentBase64: string;
}

/**
 * Custom Obsidian view that displays encrypted file content in read-only mode
 * when decryption has failed.
 */
export class EncryptedFileView extends ItemView {
  private filePath = '';
  private errorMessage = '';
  private rawContentBase64 = '';

  getViewType(): string {
    return ENCRYPTED_FILE_VIEW_TYPE;
  }

  getDisplayText(): string {
    return this.filePath
      ? `Encrypted: ${this.filePath}`
      : 'Encrypted File (Read-Only)';
  }

  getIcon(): string {
    return 'lock';
  }

  /**
   * Set the view content programmatically.
   */
  setContent(filePath: string, errorMessage: string, rawContent: Uint8Array): void {
    this.filePath = filePath;
    this.errorMessage = errorMessage;
    this.rawContentBase64 = uint8ArrayToBase64(rawContent);
    this.render();
  }

  async onOpen(): Promise<void> {
    this.render();
  }

  async onClose(): Promise<void> {
    const container = this.containerEl.children[1];
    if (container) {
      container.empty();
    }
  }

  getState(): EncryptedFileViewState {
    return {
      filePath: this.filePath,
      errorMessage: this.errorMessage,
      rawContentBase64: this.rawContentBase64,
    };
  }

  async setState(state: Partial<EncryptedFileViewState>, result: any): Promise<void> {
    if (state.filePath !== undefined) this.filePath = state.filePath;
    if (state.errorMessage !== undefined) this.errorMessage = state.errorMessage;
    if (state.rawContentBase64 !== undefined) this.rawContentBase64 = state.rawContentBase64;
    this.render();
    await super.setState(state, result);
  }

  /**
   * Render the view content: error banner + base64 dump.
   */
  private render(): void {
    const container = this.containerEl.children[1];
    if (!container) return;
    container.empty();

    // Error banner
    const banner = container.createEl('div', { cls: 'ocke-encrypted-view-banner' });

    const errorIcon = banner.createEl('span');
    errorIcon.textContent = '⚠ ';

    const errorText = banner.createEl('span');
    errorText.textContent = this.errorMessage || 'Decryption failed';

    if (this.filePath) {
      const fileInfo = banner.createEl('div', { cls: 'ocke-encrypted-view-banner-detail' });
      fileInfo.textContent = `File: ${this.filePath}`;
    }

    // Raw content section
    const contentSection = container.createEl('div');

    const heading = contentSection.createEl('h4', { cls: 'ocke-encrypted-view-heading' });
    heading.textContent = 'Raw On-Disk Content (Base64)';

    const codeBlock = contentSection.createEl('pre', { cls: 'ocke-encrypted-view-code' });
    const code = codeBlock.createEl('code');
    code.textContent = this.rawContentBase64 || '(no content)';
  }
}

/**
 * Register the encrypted file view type with the plugin.
 * Call this during plugin onload().
 */
export function registerEncryptedFileView(plugin: Plugin): void {
  plugin.registerView(
    ENCRYPTED_FILE_VIEW_TYPE,
    (leaf: WorkspaceLeaf) => new EncryptedFileView(leaf)
  );
}

/**
 * Open the encrypted file read-only view with specific content.
 *
 * Creates a new leaf and sets the view content to display the error
 * and raw file bytes as base64.
 *
 * @param plugin - The plugin instance
 * @param filePath - Vault-relative path of the file that failed to decrypt
 * @param errorMessage - Human-readable error description (e.g., "Decryption failed: KMS timeout")
 * @param rawContent - Raw on-disk bytes of the encrypted file
 */
export async function openEncryptedFileView(
  plugin: Plugin,
  filePath: string,
  errorMessage: string,
  rawContent: Uint8Array
): Promise<void> {
  const { workspace } = plugin.app;

  // Detach any existing encrypted view leaves for the same file
  workspace.detachLeavesOfType(ENCRYPTED_FILE_VIEW_TYPE);

  // Get or create a leaf for the view
  const leaf = workspace.getLeaf(true);
  await leaf.setViewState({
    type: ENCRYPTED_FILE_VIEW_TYPE,
    active: true,
  });

  // Set the content on the view
  const view = leaf.view;
  if (view instanceof EncryptedFileView) {
    view.setContent(filePath, errorMessage, rawContent);
  }

  // Reveal the leaf
  workspace.revealLeaf(leaf);
}

/**
 * Show the encrypted file read-only view when decryption fails.
 *
 * This is the primary entry point for displaying failed decryption results.
 * It opens a new leaf with the encrypted-file-view type, sets the error
 * and raw content on the view so the user can see what's on disk but cannot edit.
 *
 * @param plugin - The plugin instance
 * @param filePath - Vault-relative path of the file that failed to decrypt
 * @param rawContent - Raw on-disk bytes of the encrypted file
 * @param error - The error that caused decryption to fail
 */
export async function showEncryptedFileError(
  plugin: Plugin,
  filePath: string,
  rawContent: Uint8Array,
  error: Error
): Promise<void> {
  // Build error message with category if available (PluginError)
  let errorMessage: string;
  if ('category' in error && typeof (error as any).category === 'string') {
    errorMessage = `[${(error as any).category}] ${error.message}`;
  } else {
    errorMessage = error.message || 'Decryption failed';
  }

  await openEncryptedFileView(plugin, filePath, errorMessage, rawContent);
}

/**
 * Convert a Uint8Array to a base64 string.
 * Uses chunked approach to avoid call stack overflow on large arrays.
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Process in chunks to avoid maximum call stack size exceeded
  const chunkSize = 8192;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    for (let j = 0; j < chunk.length; j++) {
      binary += String.fromCharCode(chunk[j]);
    }
  }
  return btoa(binary);
}
