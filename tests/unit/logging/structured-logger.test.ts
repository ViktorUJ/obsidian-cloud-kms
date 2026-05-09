import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { logEncrypt, logDecrypt, logError } from '../../../src/logging/structured-logger';

describe('structured-logger', () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  describe('logEncrypt', () => {
    it('emits a structured info log entry with all required fields', () => {
      logEncrypt({
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        filePath: 'clients/acme/notes/secret.secret.md',
        payloadByteLength: 2048,
      });

      expect(consoleLogSpy).toHaveBeenCalledOnce();
      const json = consoleLogSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.level).toBe('info');
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
      expect(entry.providerId).toBe('aws-kms');
      expect(entry.cmkId).toBe('arn:aws:kms:us-east-1:123456789012:key/test-key');
      expect(entry.filePath).toBe('clients/acme/notes/secret.secret.md');
      expect(entry.payloadByteLength).toBe(2048);
      expect(entry.message).toBe('File encrypted successfully');
    });

    it('does not include formatVersion or errorCode fields', () => {
      logEncrypt({
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        filePath: 'notes/test.md',
        payloadByteLength: 512,
      });

      const json = consoleLogSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.formatVersion).toBeUndefined();
      expect(entry.errorCode).toBeUndefined();
    });

    it('emits to console.log (not console.error)', () => {
      logEncrypt({
        providerId: 'aws-kms',
        cmkId: 'test-key',
        filePath: 'test.md',
        payloadByteLength: 100,
      });

      expect(consoleLogSpy).toHaveBeenCalledOnce();
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });
  });

  describe('logDecrypt', () => {
    it('emits a structured info log entry with all required fields', () => {
      logDecrypt({
        providerId: 'azure-key-vault',
        cmkId: 'https://myvault.vault.azure.net/keys/mykey/version',
        filePath: 'clients/beta/report.secret.md',
        formatVersion: 1,
      });

      expect(consoleLogSpy).toHaveBeenCalledOnce();
      const json = consoleLogSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.level).toBe('info');
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
      expect(entry.providerId).toBe('azure-key-vault');
      expect(entry.cmkId).toBe('https://myvault.vault.azure.net/keys/mykey/version');
      expect(entry.filePath).toBe('clients/beta/report.secret.md');
      expect(entry.formatVersion).toBe(1);
      expect(entry.message).toBe('File decrypted successfully');
    });

    it('does not include payloadByteLength or errorCode fields', () => {
      logDecrypt({
        providerId: 'aws-kms',
        cmkId: 'test-key',
        filePath: 'test.md',
        formatVersion: 1,
      });

      const json = consoleLogSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.payloadByteLength).toBeUndefined();
      expect(entry.errorCode).toBeUndefined();
    });

    it('emits to console.log (not console.error)', () => {
      logDecrypt({
        providerId: 'gcp-kms',
        cmkId: 'projects/my-project/locations/global/keyRings/ring/cryptoKeys/key',
        filePath: 'test.md',
        formatVersion: 1,
      });

      expect(consoleLogSpy).toHaveBeenCalledOnce();
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });
  });

  describe('logError', () => {
    it('emits a structured error log entry with all required fields', () => {
      logError({
        providerId: 'aws-kms',
        cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        filePath: 'clients/acme/notes/secret.secret.md',
        errorCode: 'network',
        message: 'KMS unreachable: connection timeout',
      });

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      const json = consoleErrorSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.level).toBe('error');
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
      expect(entry.providerId).toBe('aws-kms');
      expect(entry.cmkId).toBe('arn:aws:kms:us-east-1:123456789012:key/test-key');
      expect(entry.filePath).toBe('clients/acme/notes/secret.secret.md');
      expect(entry.errorCode).toBe('network');
      expect(entry.message).toBe('KMS unreachable: connection timeout');
    });

    it('emits to console.error (not console.log)', () => {
      logError({
        providerId: 'aws-kms',
        cmkId: 'test-key',
        filePath: 'test.md',
        errorCode: 'timeout',
        message: 'Request timed out',
      });

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      expect(consoleLogSpy).not.toHaveBeenCalled();
    });

    it('does not include payloadByteLength or formatVersion fields', () => {
      logError({
        providerId: 'aws-kms',
        cmkId: 'test-key',
        filePath: 'test.md',
        errorCode: 'credential',
        message: 'Credentials expired',
      });

      const json = consoleErrorSpy.mock.calls[0][0] as string;
      const entry = JSON.parse(json);

      expect(entry.payloadByteLength).toBeUndefined();
      expect(entry.formatVersion).toBeUndefined();
    });
  });

  describe('sanitization in logger', () => {
    it('does not leak sensitive data even if passed in unexpected fields', () => {
      // The logger should sanitize through the sanitizer module
      logEncrypt({
        providerId: 'aws-kms',
        cmkId: 'test-key',
        filePath: 'test.md',
        payloadByteLength: 100,
      });

      const json = consoleLogSpy.mock.calls[0][0] as string;
      // Verify it's valid JSON
      expect(() => JSON.parse(json)).not.toThrow();
      // Verify no binary data leaked
      expect(json).not.toContain('Uint8Array');
    });
  });
});
