import { describe, it, expect } from 'vitest';
import { sanitizeValue, sanitizeLogPayload } from '../../../src/logging/sanitizer';

describe('sanitizer', () => {
  describe('sanitizeValue', () => {
    it('redacts Uint8Array values', () => {
      const bytes = new Uint8Array([1, 2, 3, 4]);
      expect(sanitizeValue(bytes)).toBe('[REDACTED binary data]');
    });

    it('redacts ArrayBuffer values', () => {
      const buffer = new ArrayBuffer(16);
      expect(sanitizeValue(buffer)).toBe('[REDACTED binary data]');
    });

    it('redacts sensitive field names regardless of value', () => {
      expect(sanitizeValue('some-value', 'plaintextDek')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'dek')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'wrappedDek')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'authTag')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'ciphertext')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'plaintext')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'secretKey')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'accessKey')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'sessionToken')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'password')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'credential')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'credentials')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'token')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'secret')).toBe('[REDACTED]');
      expect(sanitizeValue('some-value', 'privateKey')).toBe('[REDACTED]');
    });

    it('passes through safe string values', () => {
      expect(sanitizeValue('hello world')).toBe('hello world');
      expect(sanitizeValue('aws-kms')).toBe('aws-kms');
    });

    it('redacts AWS access key IDs in strings', () => {
      const input = 'key is AKIAIOSFODNN7EXAMPLE here';
      const result = sanitizeValue(input) as string;
      expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(result).toContain('[REDACTED]');
    });

    it('redacts Bearer tokens in strings', () => {
      const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test';
      const result = sanitizeValue(input) as string;
      expect(result).not.toContain('eyJhbGciOiJIUzI1NiJ9.test');
      expect(result).toContain('[REDACTED]');
    });

    it('passes through numbers unchanged', () => {
      expect(sanitizeValue(42)).toBe(42);
      expect(sanitizeValue(0)).toBe(0);
    });

    it('passes through booleans unchanged', () => {
      expect(sanitizeValue(true)).toBe(true);
      expect(sanitizeValue(false)).toBe(false);
    });

    it('passes through null and undefined unchanged', () => {
      expect(sanitizeValue(null)).toBe(null);
      expect(sanitizeValue(undefined)).toBe(undefined);
    });

    it('recursively sanitizes arrays', () => {
      const input = [new Uint8Array([1, 2]), 'safe', 42];
      const result = sanitizeValue(input) as unknown[];
      expect(result[0]).toBe('[REDACTED binary data]');
      expect(result[1]).toBe('safe');
      expect(result[2]).toBe(42);
    });

    it('recursively sanitizes nested objects', () => {
      const input = {
        providerId: 'aws-kms',
        dek: new Uint8Array([1, 2, 3]),
        nested: {
          plaintext: 'secret content',
        },
      };
      const result = sanitizeValue(input) as Record<string, unknown>;
      expect(result.providerId).toBe('aws-kms');
      expect(result.dek).toBe('[REDACTED]');
      expect((result.nested as Record<string, unknown>).plaintext).toBe('[REDACTED]');
    });
  });

  describe('sanitizeLogPayload', () => {
    it('sanitizes a typical encrypt log payload', () => {
      const payload = {
        level: 'info',
        timestamp: '2024-01-01T00:00:00.000Z',
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        filePath: 'notes/secret.md',
        payloadByteLength: 1024,
        message: 'File encrypted successfully',
      };
      const result = sanitizeLogPayload(payload);
      expect(result.level).toBe('info');
      expect(result.providerId).toBe('aws-kms');
      expect(result.cmkId).toBe('arn:aws:kms:us-east-1:123456789012:key/test-key');
      expect(result.filePath).toBe('notes/secret.md');
      expect(result.payloadByteLength).toBe(1024);
    });

    it('strips sensitive fields from log payload', () => {
      const payload = {
        level: 'info',
        providerId: 'aws-kms',
        plaintext: 'this should not appear',
        dek: new Uint8Array(32),
        wrappedDek: new Uint8Array(256),
        authTag: new Uint8Array(16),
      };
      const result = sanitizeLogPayload(payload);
      expect(result.level).toBe('info');
      expect(result.providerId).toBe('aws-kms');
      expect(result.plaintext).toBe('[REDACTED]');
      expect(result.dek).toBe('[REDACTED]');
      expect(result.wrappedDek).toBe('[REDACTED]');
      expect(result.authTag).toBe('[REDACTED]');
    });

    it('does not modify the original payload object', () => {
      const payload = {
        level: 'info',
        providerId: 'aws-kms',
        dek: new Uint8Array(32),
      };
      sanitizeLogPayload(payload);
      expect(payload.dek).toBeInstanceOf(Uint8Array);
    });
  });
});
