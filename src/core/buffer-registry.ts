/**
 * BufferRegistry — tracks all active SecureBuffer instances for lifecycle management.
 *
 * On plugin unload or application quit, `releaseAll()` force-releases every
 * registered buffer, ensuring no plaintext or DEK material lingers in memory.
 *
 * Buffers are automatically removed from the registry when released individually.
 */

import { SecureBuffer } from './secure-buffer';

export class BufferRegistry {
  private readonly _buffers: Set<SecureBuffer> = new Set();

  /**
   * Register a SecureBuffer for lifecycle tracking.
   * Returns the same buffer for chaining convenience.
   */
  register(buffer: SecureBuffer): SecureBuffer {
    if (!buffer.isReleased) {
      this._buffers.add(buffer);
    }
    return buffer;
  }

  /**
   * Unregister a buffer (called after individual release).
   */
  unregister(buffer: SecureBuffer): void {
    this._buffers.delete(buffer);
  }

  /**
   * Force-release all registered buffers.
   * Called on plugin unload / app quit to ensure zero cleartext in memory.
   */
  releaseAll(): void {
    for (const buffer of this._buffers) {
      if (!buffer.isReleased) {
        buffer.release();
      }
    }
    this._buffers.clear();
  }

  /**
   * Number of currently tracked (unreleased) buffers.
   */
  get size(): number {
    return this._buffers.size;
  }

  /**
   * Create a new SecureBuffer, register it, and return it.
   * Convenience method combining allocation and registration.
   */
  create(data: Uint8Array): SecureBuffer {
    const buffer = SecureBuffer.from(data);
    this.register(buffer);
    return buffer;
  }
}
