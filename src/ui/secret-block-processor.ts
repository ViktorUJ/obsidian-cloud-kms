/**
 * Markdown code block processor for ```ocke-v1 blocks.
 * Renders encrypted blocks as visual widgets in Reading view and Live Preview.
 */

import { Plugin, MarkdownPostProcessorContext } from 'obsidian';
import type { CryptoEngine, EncryptionContext } from '../types';
import { decodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { FORMAT_VERSION } from '../constants';

const decryptionCache = new Map<string, { plaintext: string | null; error: boolean }>();

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

      const container = el.createDiv({ cls: 'ocke-secret-block' });
      const header = container.createDiv({ cls: 'ocke-secret-block-header' });
      const content = container.createEl('pre', { cls: 'ocke-secret-block-content' });

      const cached = decryptionCache.get(base64Content);
      if (cached) {
        if (cached.error) {
          renderLocked(header, content, base64Content);
        } else {
          renderDecrypted(header, content, cached.plaintext ?? '');
        }
        return;
      }

      header.addClass('ocke-secret-block-header--loading');
      header.textContent = '⏳ secret (decrypting...)';
      content.textContent = '...';
      content.addClass('ocke-secret-block-content--locked');

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
  header.removeClass('ocke-secret-block-header--loading');
  header.removeClass('ocke-secret-block-header--locked');
  header.addClass('ocke-secret-block-header--decrypted');
  header.textContent = '🔓 secret (decrypted)';
  content.removeClass('ocke-secret-block-content--locked');
  content.textContent = plaintext;
}

function renderLocked(header: HTMLElement, content: HTMLElement, base64Content: string): void {
  header.removeClass('ocke-secret-block-header--loading');
  header.removeClass('ocke-secret-block-header--decrypted');
  header.addClass('ocke-secret-block-header--locked');
  header.textContent = '🔒 secret (locked — no key access)';

  const preview = base64Content.length > 80 ? base64Content.slice(0, 80) + '…' : base64Content;
  content.addClass('ocke-secret-block-content--locked');
  content.textContent = preview;
}

export function clearDecryptionCache(): void {
  decryptionCache.clear();
}
