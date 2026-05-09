/**
 * SecureBuffer — wraps a Uint8Array with guaranteed zero-fill on release.
 *
 * Prevents plaintext and DEK material from lingering in GC-managed memory.
 * After release(), accessing `bytes` throws to prevent use-after-free.
 *
 * Zero-fill uses a two-pass pattern (random fill then zero fill) to defeat
 * compiler optimizations that might elide a simple zero-fill of a buffer
 * that is never read again.
 */

import type { SecureBuffer as ISecureBuffer } from '../types';

export class SecureBuffer implements ISecureBuffer {
  private _buffer: Uint8Array;
  private _released = false;

  /**
   * Create a SecureBuffer wrapping the given data.
   * The caller should not retain a reference to the input array.
   */
  constructor(data: Uint8Array) {
    // Copy the data into our own buffer to avoid shared references
    this._buffer = new Uint8Array(data.length);
    this._buffer.set(data);
  }

  /**
   * Access the underlying bytes.
   * @throws Error if the buffer has been released.
   */
  get bytes(): Uint8Array {
    if (this._released) {
      throw new Error('SecureBuffer: access after release');
    }
    return this._buffer;
  }

  /**
   * Length of the buffer in bytes.
   * @throws Error if the buffer has been released.
   */
  get length(): number {
    if (this._released) {
      throw new Error('SecureBuffer: access after release');
    }
    return this._buffer.length;
  }

  /** Whether the buffer has been released. */
  get isReleased(): boolean {
    return this._released;
  }

  /**
   * Zero-fill the buffer and mark as released.
   *
   * Uses a two-pass wipe: first fills with random bytes (to prevent the
   * compiler from optimizing away a "dead store" of zeros), then fills
   * with zeros. This ensures the sensitive data is actually overwritten.
   *
   * Calling release() on an already-released buffer is a no-op.
   */
  release(): void {
    if (this._released) {
      return;
    }

    // Pass 1: fill with random bytes to defeat dead-store elimination
    crypto.getRandomValues(this._buffer);
    // Pass 2: zero-fill
    this._buffer.fill(0);

    this._released = true;
  }

  /**
   * Create a SecureBuffer from raw bytes.
   * Convenience factory that also zeroes the source array after copying.
   */
  static from(data: Uint8Array): SecureBuffer {
    const buf = new SecureBuffer(data);
    // Zero the source to avoid leaving a copy in the caller's memory
    crypto.getRandomValues(data);
    data.fill(0);
    return buf;
  }

  /**
   * Allocate a new SecureBuffer of the given size, filled with zeros.
   */
  static alloc(size: number): SecureBuffer {
    return new SecureBuffer(new Uint8Array(size));
  }
}
