/**
 * Markdown code block processor for ```ocke-v1 blocks.
 *
 * Registers a code block processor that renders encrypted blocks
 * as visual widgets in both Reading view and Live Preview mode.
 *
 * Key principle: the actual document text is NEVER modified.
 * The processor only controls how the block is rendered visually.
 *
 * - If decryption succeeds: shows 🔓 header + decrypted plaintext
 * - If decryption fails: shows 🔒 header + truncated ciphertext
 */

import { Plugin, MarkdownPostProcessorContext } from 'obsidian';
import type { CryptoEngine, EncryptionContext } from '../types';
import { decodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { FORMAT_VERSION } from '../constants';

/**
 * Cache of decrypted content keyed by base64 content.
 */
const decryptionCache = new Map<string, { plaintext: string | null; error: boolean }>();

/**
 * Register the ocke-v1 code block processor.
 *
 * This makes Obsidian render ```ocke-v1 blocks with a custom visual
 * instead of showing raw base64 text.
 */
export function registerSecretBlockProcessor(
  plugin: Plugin,
  cryptoEngine: CryptoEngine,
  getVaultName: () => string,
  getFilePath: () => string
): void {
  plugin.registerMarkdownCodeBlockProcessor(
    'ocke-v1',
    async (source: string, el: HTMLElement, _ctx: MarkdownPostProcessorContext) => {
      const base64Content = source.trim();

      // Create container
      const container = el.createDiv({ cls: 'ocke-secret-block' });
      container.style.border = '1px solid var(--background-modifier-border)';
      container.style.borderRadius = '4px';
      container.style.overflow = 'hidden';

      // Header
      const header = container.createDiv({ cls: 'ocke-secret-block-header' });
      header.style.padding = '4px 8px';
      header.style.fontSize = '0.8em';
      header.style.fontWeight = 'bold';
      header.style.display = 'flex';
      header.style.alignItems = 'center';
      header.style.gap = '4px';

      // Content area
      const content = container.createEl('pre', { cls: 'ocke-secret-block-content' });
      content.style.padding = '8px';
      content.style.margin = '0';
      content.style.whiteSpace = 'pre-wrap';
      content.style.wordBreak = 'break-word';
      content.style.fontFamily = 'var(--font-monospace)';
      content.style.fontSize = '0.9em';
      content.style.background = 'var(--background-secondary)';

      // Check cache first
      const cached = decryptionCache.get(base64Content);
      if (cached) {
        if (cached.error) {
          renderLocked(header, content, base64Content);
        } else {
          renderDecrypted(header, content, cached.plaintext ?? '');
        }
        return;
      }

      // Show loading state
      header.style.background = 'var(--background-modifier-border)';
      header.style.color = 'var(--text-muted)';
      header.textContent = '⏳ secret (decrypting...)';
      content.textContent = '...';
      content.style.color = 'var(--text-muted)';

      // Attempt decryption
      try {
        const fullBlock = '```ocke-v1\n' + base64Content + '\n```';
        const binaryData = decodeInlineBlock(fullBlock);

        if (!binaryData) {
          decryptionCache.set(base64Content, { plaintext: null, error: true });
          renderLocked(header, content, base64Content);
          return;
        }

        const record = parse(binaryData);
        const context: EncryptionContext = {
          vaultName: getVaultName(),
          filePath: getFilePath(),
          formatVersion: FORMAT_VERSION,
        };

        const plaintextBytes = await cryptoEngine.decrypt(record, context);
        const plaintext = new TextDecoder().decode(plaintextBytes);

        decryptionCache.set(base64Content, { plaintext, error: false });
        renderDecrypted(header, content, plaintext);
      } catch {
        decryptionCache.set(base64Content, { plaintext: null, error: true });
        renderLocked(header, content, base64Content);
      }
    }
  );
}

function renderDecrypted(header: HTMLElement, content: HTMLElement, plaintext: string): void {
  header.style.background = 'var(--interactive-accent)';
  header.style.color = 'var(--text-on-accent)';
  header.textContent = '🔓 secret (decrypted)';

  content.textContent = plaintext;
  content.style.color = '';
}

function renderLocked(header: HTMLElement, content: HTMLElement, base64Content: string): void {
  header.style.background = 'var(--background-modifier-error)';
  header.style.color = 'var(--text-error)';
  header.textContent = '🔒 secret (locked — no key access)';

  const preview = base64Content.length > 80
    ? base64Content.slice(0, 80) + '…'
    : base64Content;
  content.textContent = preview;
  content.style.color = 'var(--text-muted)';
  content.style.fontStyle = 'italic';
}

/**
 * Clear the decryption cache.
 */
export function clearDecryptionCache(): void {
  decryptionCache.clear();
}
