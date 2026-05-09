import { describe, it, expect } from 'vitest';
import { SecureBuffer } from '../../../src/core/secure-buffer';

describe('SecureBuffer', () => {
  it('should store and return bytes correctly', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const buf = new SecureBuffer(data);

    expect(buf.bytes).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    expect(buf.length).toBe(5);
    expect(buf.isReleased).toBe(false);
  });

  it('should copy input data (not share reference)', () => {
    const data = new Uint8Array([10, 20, 30]);
    const buf = new SecureBuffer(data);

    // Mutating the original should not affect the buffer
    data[0] = 99;
    expect(buf.bytes[0]).toBe(10);
  });

  it('should zero-fill buffer on release', () => {
    const data = new Uint8Array([0xFF, 0xAB, 0xCD, 0xEF]);
    const buf = new SecureBuffer(data);

    // Get a reference to the internal buffer before release
    const internalRef = buf.bytes;
    buf.release();

    // The internal buffer should be zeroed
    for (let i = 0; i < internalRef.length; i++) {
      expect(internalRef[i]).toBe(0);
    }
  });

  it('should mark buffer as released after release()', () => {
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));
    expect(buf.isReleased).toBe(false);

    buf.release();
    expect(buf.isReleased).toBe(true);
  });

  it('should throw on bytes access after release', () => {
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));
    buf.release();

    expect(() => buf.bytes).toThrow('SecureBuffer: access after release');
  });

  it('should throw on length access after release', () => {
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));
    buf.release();

    expect(() => buf.length).toThrow('SecureBuffer: access after release');
  });

  it('should be a no-op when release() is called twice', () => {
    const buf = new SecureBuffer(new Uint8Array([1, 2, 3]));
    buf.release();

    // Second release should not throw
    expect(() => buf.release()).not.toThrow();
    expect(buf.isReleased).toBe(true);
  });

  it('should handle empty buffer', () => {
    const buf = new SecureBuffer(new Uint8Array(0));
    expect(buf.length).toBe(0);
    expect(buf.bytes.length).toBe(0);

    buf.release();
    expect(buf.isReleased).toBe(true);
  });

  describe('SecureBuffer.from()', () => {
    it('should create buffer and zero the source array', () => {
      const source = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
      const buf = SecureBuffer.from(source);

      // Buffer should have the original data
      expect(buf.bytes).toEqual(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));

      // Source should be zeroed
      for (let i = 0; i < source.length; i++) {
        expect(source[i]).toBe(0);
      }
    });
  });

  describe('SecureBuffer.alloc()', () => {
    it('should create a zero-filled buffer of given size', () => {
      const buf = SecureBuffer.alloc(16);
      expect(buf.length).toBe(16);
      expect(buf.bytes.every(b => b === 0)).toBe(true);
    });
  });
});
