import { describe, it, expect } from 'vitest';
import { SecureBuffer } from '../../../src/core/secure-buffer';
import { BufferRegistry } from '../../../src/core/buffer-registry';

describe('BufferRegistry', () => {
  it('should start with zero tracked buffers', () => {
    const registry = new BufferRegistry();
    expect(registry.size).toBe(0);
  });

  it('should track registered buffers', () => {
    const registry = new BufferRegistry();
    const buf1 = new SecureBuffer(new Uint8Array([1, 2, 3]));
    const buf2 = new SecureBuffer(new Uint8Array([4, 5, 6]));

    registry.register(buf1);
    registry.register(buf2);

    expect(registry.size).toBe(2);
  });

  it('should not register already-released buffers', () => {
    const registry = new BufferRegistry();
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));
    buf.release();

    registry.register(buf);
    expect(registry.size).toBe(0);
  });

  it('should unregister buffers', () => {
    const registry = new BufferRegistry();
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));

    registry.register(buf);
    expect(registry.size).toBe(1);

    registry.unregister(buf);
    expect(registry.size).toBe(0);
  });

  it('should release all registered buffers on releaseAll()', () => {
    const registry = new BufferRegistry();
    const buf1 = new SecureBuffer(new Uint8Array([1, 2, 3]));
    const buf2 = new SecureBuffer(new Uint8Array([4, 5, 6]));
    const buf3 = new SecureBuffer(new Uint8Array([7, 8, 9]));

    registry.register(buf1);
    registry.register(buf2);
    registry.register(buf3);

    // Get references to internal buffers before release
    const ref1 = buf1.bytes;
    const ref2 = buf2.bytes;
    const ref3 = buf3.bytes;

    registry.releaseAll();

    // All buffers should be released
    expect(buf1.isReleased).toBe(true);
    expect(buf2.isReleased).toBe(true);
    expect(buf3.isReleased).toBe(true);

    // All internal buffers should be zeroed
    expect(ref1.every(b => b === 0)).toBe(true);
    expect(ref2.every(b => b === 0)).toBe(true);
    expect(ref3.every(b => b === 0)).toBe(true);

    // Registry should be empty
    expect(registry.size).toBe(0);
  });

  it('should handle releaseAll() with some already-released buffers', () => {
    const registry = new BufferRegistry();
    const buf1 = new SecureBuffer(new Uint8Array([1, 2, 3]));
    const buf2 = new SecureBuffer(new Uint8Array([4, 5, 6]));

    registry.register(buf1);
    registry.register(buf2);

    // Release one manually
    buf1.release();

    // releaseAll should still work without error
    expect(() => registry.releaseAll()).not.toThrow();
    expect(buf2.isReleased).toBe(true);
    expect(registry.size).toBe(0);
  });

  it('should handle releaseAll() on empty registry', () => {
    const registry = new BufferRegistry();
    expect(() => registry.releaseAll()).not.toThrow();
    expect(registry.size).toBe(0);
  });

  describe('create()', () => {
    it('should create a buffer, register it, and zero the source', () => {
      const registry = new BufferRegistry();
      const source = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]);

      const buf = registry.create(source);

      // Buffer should have the original data
      expect(buf.bytes).toEqual(new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]));

      // Source should be zeroed
      expect(source.every(b => b === 0)).toBe(true);

      // Buffer should be tracked
      expect(registry.size).toBe(1);
    });

    it('should release created buffers on releaseAll()', () => {
      const registry = new BufferRegistry();
      const buf = registry.create(new Uint8Array([1, 2, 3, 4]));

      const ref = buf.bytes;
      registry.releaseAll();

      expect(buf.isReleased).toBe(true);
      expect(ref.every(b => b === 0)).toBe(true);
    });
  });

  it('should return the buffer from register() for chaining', () => {
    const registry = new BufferRegistry();
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));

    const returned = registry.register(buf);
    expect(returned).toBe(buf);
  });
});
