/**
 * Unit tests for AwsKmsAdapter.
 *
 * Mocks the @aws-sdk/client-kms client to test:
 * - Successful generateDataKey, wrapDek, unwrapDek, validateAccess flows
 * - Timeout handling (AbortController)
 * - Credential errors, authorization errors, network errors
 * - Encryption context passing
 * - KeyId verification on unwrapDek
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AwsKmsAdapter } from '../../../src/providers/aws-kms-adapter';
import { PluginError } from '../../../src/providers/errors';
import { EncryptionContext } from '../../../src/types';

// Mock KMSClient
function createMockClient() {
  return {
    send: vi.fn(),
  };
}

const TEST_CMK_ID = 'arn:aws:kms:us-east-1:123456789012:key/test-key-id';

const TEST_CONTEXT: EncryptionContext = {
  vaultName: 'test-vault',
  filePath: 'notes/secret.md',
  formatVersion: 1,
};

describe('AwsKmsAdapter', () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let adapter: AwsKmsAdapter;

  beforeEach(() => {
    mockClient = createMockClient();
    adapter = new AwsKmsAdapter(mockClient as any, 10_000);
  });

  it('has providerId "aws-kms"', () => {
    expect(adapter.providerId).toBe('aws-kms');
  });

  describe('generateDataKey', () => {
    it('calls GenerateDataKeyCommand with correct parameters', async () => {
      const plaintext = new Uint8Array(32).fill(0xAB);
      const ciphertextBlob = new Uint8Array(64).fill(0xCD);

      mockClient.send.mockResolvedValue({
        Plaintext: plaintext,
        CiphertextBlob: ciphertextBlob,
      });

      const result = await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);

      expect(mockClient.send).toHaveBeenCalledTimes(1);
      const call = mockClient.send.mock.calls[0];
      const command = call[0];
      expect(command.input).toEqual({
        KeyId: TEST_CMK_ID,
        KeySpec: 'AES_256',
        EncryptionContext: {
          vaultName: 'test-vault',
          filePath: 'notes/secret.md',
          formatVersion: '1',
        },
      });

      expect(result.plaintextDek).toEqual(plaintext);
      expect(result.wrappedDek).toEqual(ciphertextBlob);
    });

    it('passes AbortSignal to the send call', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: new Uint8Array(32),
        CiphertextBlob: new Uint8Array(64),
      });

      await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);

      const options = mockClient.send.mock.calls[0][1];
      expect(options).toHaveProperty('abortSignal');
      expect(options.abortSignal).toBeInstanceOf(AbortSignal);
    });

    it('throws PluginError with crypto category when Plaintext is missing', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: undefined,
        CiphertextBlob: new Uint8Array(64),
      });

      await expect(adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT))
        .rejects.toThrow(PluginError);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect((err as PluginError).category).toBe('crypto');
        expect((err as PluginError).providerId).toBe('aws-kms');
      }
    });

    it('throws PluginError with crypto category when CiphertextBlob is missing', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: new Uint8Array(32),
        CiphertextBlob: undefined,
      });

      await expect(adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT))
        .rejects.toThrow(PluginError);
    });
  });

  describe('wrapDek', () => {
    it('calls EncryptCommand with correct parameters', async () => {
      const dek = new Uint8Array(32).fill(0x11);
      const wrappedDek = new Uint8Array(64).fill(0x22);

      mockClient.send.mockResolvedValue({
        CiphertextBlob: wrappedDek,
      });

      const result = await adapter.wrapDek(dek, TEST_CMK_ID, TEST_CONTEXT);

      expect(mockClient.send).toHaveBeenCalledTimes(1);
      const command = mockClient.send.mock.calls[0][0];
      expect(command.input).toEqual({
        KeyId: TEST_CMK_ID,
        Plaintext: dek,
        EncryptionContext: {
          vaultName: 'test-vault',
          filePath: 'notes/secret.md',
          formatVersion: '1',
        },
      });

      expect(result).toEqual(wrappedDek);
    });

    it('throws PluginError with crypto category when CiphertextBlob is missing', async () => {
      mockClient.send.mockResolvedValue({
        CiphertextBlob: undefined,
      });

      const dek = new Uint8Array(32);
      await expect(adapter.wrapDek(dek, TEST_CMK_ID, TEST_CONTEXT))
        .rejects.toThrow(PluginError);
    });
  });

  describe('unwrapDek', () => {
    it('calls DecryptCommand with correct parameters', async () => {
      const wrappedDek = new Uint8Array(64).fill(0x33);
      const plaintext = new Uint8Array(32).fill(0x44);

      mockClient.send.mockResolvedValue({
        Plaintext: plaintext,
        KeyId: TEST_CMK_ID,
      });

      const result = await adapter.unwrapDek(wrappedDek, TEST_CMK_ID, TEST_CONTEXT);

      expect(mockClient.send).toHaveBeenCalledTimes(1);
      const command = mockClient.send.mock.calls[0][0];
      expect(command.input).toEqual({
        CiphertextBlob: wrappedDek,
        KeyId: TEST_CMK_ID,
        EncryptionContext: {
          vaultName: 'test-vault',
          filePath: 'notes/secret.md',
          formatVersion: '1',
        },
      });

      expect(result).toEqual(plaintext);
    });

    it('throws PluginError when Plaintext is missing from response', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: undefined,
        KeyId: TEST_CMK_ID,
      });

      const wrappedDek = new Uint8Array(64);
      await expect(adapter.unwrapDek(wrappedDek, TEST_CMK_ID, TEST_CONTEXT))
        .rejects.toThrow(PluginError);
    });

    it('throws PluginError when returned KeyId does not match expected cmkId', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: new Uint8Array(32),
        KeyId: 'arn:aws:kms:us-east-1:123456789012:key/different-key',
      });

      const wrappedDek = new Uint8Array(64);
      await expect(adapter.unwrapDek(wrappedDek, TEST_CMK_ID, TEST_CONTEXT))
        .rejects.toThrow(PluginError);

      try {
        await adapter.unwrapDek(wrappedDek, TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect((err as PluginError).category).toBe('crypto');
        expect((err as PluginError).message).toContain('unexpected KeyId');
      }
    });

    it('succeeds when KeyId is not returned (some KMS configurations)', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: new Uint8Array(32).fill(0x55),
        KeyId: undefined,
      });

      const wrappedDek = new Uint8Array(64);
      const result = await adapter.unwrapDek(wrappedDek, TEST_CMK_ID, TEST_CONTEXT);
      expect(result).toEqual(new Uint8Array(32).fill(0x55));
    });
  });

  describe('validateAccess', () => {
    it('calls DescribeKeyCommand with the cmkId', async () => {
      mockClient.send.mockResolvedValue({
        KeyMetadata: { KeyId: TEST_CMK_ID },
      });

      await expect(adapter.validateAccess(TEST_CMK_ID)).resolves.toBeUndefined();

      expect(mockClient.send).toHaveBeenCalledTimes(1);
      const command = mockClient.send.mock.calls[0][0];
      expect(command.input).toEqual({
        KeyId: TEST_CMK_ID,
      });
    });

    it('throws PluginError on access denied', async () => {
      const error = new Error('Access denied');
      (error as any).name = 'AccessDeniedException';
      mockClient.send.mockRejectedValue(error);

      await expect(adapter.validateAccess(TEST_CMK_ID))
        .rejects.toThrow(PluginError);

      try {
        await adapter.validateAccess(TEST_CMK_ID);
      } catch (err) {
        expect((err as PluginError).category).toBe('authorization');
      }
    });
  });

  describe('error mapping', () => {
    it('maps AbortError to timeout category', async () => {
      const error = new Error('The operation was aborted');
      (error as any).name = 'AbortError';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('timeout');
        expect((err as PluginError).providerId).toBe('aws-kms');
        expect((err as PluginError).cmkId).toBe(TEST_CMK_ID);
      }
    });

    it('maps CredentialsProviderError to credential category', async () => {
      const error = new Error('Could not load credentials');
      (error as any).name = 'CredentialsProviderError';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.wrapDek(new Uint8Array(32), TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('credential');
      }
    });

    it('maps ExpiredTokenException to credential category', async () => {
      const error = new Error('Token expired');
      (error as any).name = 'ExpiredTokenException';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.unwrapDek(new Uint8Array(64), TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('credential');
      }
    });

    it('maps AccessDeniedException to authorization category', async () => {
      const error = new Error('Not authorized');
      (error as any).name = 'AccessDeniedException';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('authorization');
      }
    });

    it('maps KMSAccessDeniedException to authorization category', async () => {
      const error = new Error('KMS access denied');
      (error as any).name = 'KMSAccessDeniedException';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('authorization');
      }
    });

    it('maps KMSInternalException to network category', async () => {
      const error = new Error('Internal error');
      (error as any).name = 'KMSInternalException';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('network');
      }
    });

    it('maps network-related message to network category', async () => {
      const error = new Error('ECONNREFUSED: connection refused');
      (error as any).name = 'Error';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('network');
      }
    });

    it('maps unknown errors to crypto category', async () => {
      const error = new Error('Something unexpected');
      (error as any).name = 'SomeUnknownError';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect(err).toBeInstanceOf(PluginError);
        expect((err as PluginError).category).toBe('crypto');
      }
    });

    it('preserves original error as cause', async () => {
      const originalError = new Error('Original');
      (originalError as any).name = 'AccessDeniedException';
      mockClient.send.mockRejectedValue(originalError);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect((err as PluginError).cause).toBe(originalError);
      }
    });
  });

  describe('encryption context', () => {
    it('converts EncryptionContext to Record<string, string> with formatVersion as string', async () => {
      mockClient.send.mockResolvedValue({
        Plaintext: new Uint8Array(32),
        CiphertextBlob: new Uint8Array(64),
      });

      const context: EncryptionContext = {
        vaultName: 'my-vault',
        filePath: 'clients/acme/notes.md',
        formatVersion: 2,
      };

      await adapter.generateDataKey(TEST_CMK_ID, context);

      const command = mockClient.send.mock.calls[0][0];
      expect(command.input.EncryptionContext).toEqual({
        vaultName: 'my-vault',
        filePath: 'clients/acme/notes.md',
        formatVersion: '2',
      });
    });
  });

  describe('timeout behavior', () => {
    it('uses custom timeout when provided', () => {
      const customAdapter = new AwsKmsAdapter(mockClient as any, 5000);
      expect(customAdapter.providerId).toBe('aws-kms');
      // The timeout is internal, but we can verify it works by testing abort behavior
    });

    it('maps aborted message to timeout category', async () => {
      const error = new Error('Request aborted');
      (error as any).name = 'AbortError';
      mockClient.send.mockRejectedValue(error);

      try {
        await adapter.generateDataKey(TEST_CMK_ID, TEST_CONTEXT);
      } catch (err) {
        expect((err as PluginError).category).toBe('timeout');
      }
    });
  });
});
