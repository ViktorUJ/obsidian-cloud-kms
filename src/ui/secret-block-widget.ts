/**
 * CodeMirror ViewPlugin that renders ```ocke-v1 blocks as visual "secret" widgets.
 *
 * Key principle: the actual document text is NEVER modified.
 * The encrypted data stays on disk and in the editor buffer at all times.
 * This plugin only provides a visual overlay (widget decoration) that shows
 * the decrypted content when the key is available, or a "locked" indicator otherwise.
 */

import {
  ViewPlugin,
  ViewUpdate,
  WidgetType,
  Decoration,
  DecorationSet,
  EditorView,
} from '@codemirror/view';
import { RangeSetBuilder } from '@codemirror/state';
import type { CryptoEngine, EncryptionContext } from '../types';
import { decodeInlineBlock } from '../format/inline-codec';
import { parse } from '../format/parser';
import { FORMAT_VERSION } from '../constants';

/**
 * Regex to find ```ocke-v1 blocks with their positions.
 */
const ENCRYPTED_BLOCK_REGEX = /```ocke-v1\n([\s\S]*?)\n```/g;

/**
 * Cache of decrypted content keyed by base64 content.
 */
const decryptionCache = new Map<string, { plaintext: string | null; error: boolean }>();

/**
 * Widget that displays decrypted content inside a styled container.
 */
class DecryptedBlockWidget extends WidgetType {
  constructor(
    private readonly plaintext: string | null,
    private readonly isLocked: boolean,
    private readonly encryptedPreview: string
  ) {
    super();
  }

  toDOM(): HTMLElement {
    const container = document.createElement('div');
    container.className = 'ocke-secret-block';
    container.style.border = '1px solid var(--background-modifier-border)';
    container.style.borderRadius = '4px';
    container.style.margin = '4px 0';
    container.style.overflow = 'hidden';

    // Header
    const header = document.createElement('div');
    header.style.padding = '4px 8px';
    header.style.fontSize = '0.8em';
    header.style.fontWeight = 'bold';
    header.style.display = 'flex';
    header.style.alignItems = 'center';
    header.style.gap = '4px';

    if (this.isLocked) {
      header.style.background = 'var(--background-modifier-error)';
      header.style.color = 'var(--text-error)';
      header.textContent = '🔒 secret (locked — no key access)';
    } else if (this.plaintext === null) {
      header.style.background = 'var(--background-modifier-border)';
      header.style.color = 'var(--text-muted)';
      header.textContent = '⏳ secret (decrypting...)';
    } else {
      header.style.background = 'var(--interactive-accent)';
      header.style.color = 'var(--text-on-accent)';
      header.textContent = '🔓 secret (decrypted)';
    }

    container.appendChild(header);

    // Content
    const content = document.createElement('pre');
    content.style.padding = '8px';
    content.style.margin = '0';
    content.style.whiteSpace = 'pre-wrap';
    content.style.wordBreak = 'break-word';
    content.style.fontFamily = 'var(--font-monospace)';
    content.style.fontSize = '0.9em';
    content.style.background = 'var(--background-secondary)';

    if (this.isLocked) {
      const preview = this.encryptedPreview.length > 80
        ? this.encryptedPreview.slice(0, 80) + '…'
        : this.encryptedPreview;
      content.textContent = preview;
      content.style.color = 'var(--text-muted)';
      content.style.fontStyle = 'italic';
    } else if (this.plaintext === null) {
      content.textContent = '...';
      content.style.color = 'var(--text-muted)';
    } else {
      content.textContent = this.plaintext;
    }

    container.appendChild(content);
    return container;
  }

  eq(other: DecryptedBlockWidget): boolean {
    return (
      this.plaintext === other.plaintext &&
      this.isLocked === other.isLocked &&
      this.encryptedPreview === other.encryptedPreview
    );
  }

  ignoreEvent(): boolean {
    return false;
  }
}

/**
 * Create the secret block ViewPlugin for a given crypto engine and vault context.
 */
export function createSecretBlockViewPlugin(
  cryptoEngine: CryptoEngine,
  getVaultName: () => string,
  getFilePath: () => string
) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;

      constructor(view: EditorView) {
        this.decorations = this.buildDecorations(view);
      }

      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged || update.selectionSet) {
          this.decorations = this.buildDecorations(update.view);
        }
      }

      buildDecorations(view: EditorView): DecorationSet {
        const builder = new RangeSetBuilder<Decoration>();
        const doc = view.state.doc;
        const text = doc.toString();

        ENCRYPTED_BLOCK_REGEX.lastIndex = 0;
        let match: RegExpExecArray | null;

        const blocks: Array<{ from: number; to: number; base64: string }> = [];

        while ((match = ENCRYPTED_BLOCK_REGEX.exec(text)) !== null) {
          blocks.push({
            from: match.index,
            to: match.index + match[0].length,
            base64: match[1].trim(),
          });
        }

        const cursorPos = view.state.selection.main.head;

        for (const block of blocks) {
          // If cursor is inside this block, don't decorate — let user see raw text
          if (cursorPos >= block.from && cursorPos <= block.to) {
            continue;
          }

          const cached = decryptionCache.get(block.base64);

          if (cached) {
            const widget = new DecryptedBlockWidget(
              cached.plaintext,
              cached.error,
              block.base64
            );
            builder.add(block.from, block.to, Decoration.replace({ widget }));
          } else {
            // Show placeholder and trigger async decryption
            const widget = new DecryptedBlockWidget(null, false, block.base64);
            builder.add(block.from, block.to, Decoration.replace({ widget }));

            // Trigger decryption without blocking
            this.triggerDecrypt(block.base64, view);
          }
        }

        return builder.finish();
      }

      triggerDecrypt(base64Content: string, view: EditorView) {
        // Don't re-trigger if already in cache or pending
        if (decryptionCache.has(base64Content)) return;

        // Mark as pending to avoid duplicate requests
        decryptionCache.set(base64Content, { plaintext: null, error: false });

        const fullBlock = '```ocke-v1\n' + base64Content + '\n```';

        (async () => {
          try {
            const binaryData = decodeInlineBlock(fullBlock);
            if (!binaryData) {
              decryptionCache.set(base64Content, { plaintext: null, error: true });
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
          } catch {
            decryptionCache.set(base64Content, { plaintext: null, error: true });
          }

          // Request a re-render by scheduling a view measure
          // This is safe and won't cause infinite loops
          requestAnimationFrame(() => {
            view.requestMeasure();
          });
        })();
      }
    },
    {
      decorations: (v) => v.decorations,
    }
  );
}

/**
 * Clear the decryption cache (e.g., on plugin unload).
 */
export function clearDecryptionCache(): void {
  decryptionCache.clear();
}
