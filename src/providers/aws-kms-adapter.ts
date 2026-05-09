/**
 * AWS KMS Provider Adapter — implements ProviderAdapter using @aws-sdk/client-kms.
 *
 * Handles DEK generation, wrap/unwrap, and access validation against AWS KMS.
 * All calls use AbortController with configurable timeout (default 10s).
 * Errors are mapped to PluginError categories for structured handling.
 */

import {
  KMSClient,
  GenerateDataKeyCommand,
  EncryptCommand,
  DecryptCommand,
  DescribeKeyCommand,
} from '@aws-sdk/client-kms';
import { EncryptionContext, GenerateDataKeyResult, ProviderAdapter } from '../types';
import { PluginError } from './errors';
import { KMS_TIMEOUT_MS } from '../constants';

/**
 * Convert an EncryptionContext to the Record<string, string> format expected by KMS API.
 */
function toKmsEncryptionContext(context: EncryptionContext): Record<string, string> {
  return {
    vaultName: context.vaultName,
    filePath: context.filePath,
    formatVersion: String(context.formatVersion),
  };
}

/**
 * Map AWS SDK errors to PluginError categories.
 */
function mapAwsError(err: unknown, cmkId: string): PluginError {
  if (err instanceof PluginError) {
    return err;
  }

  const error = err as Error & { name?: string; code?: string; $metadata?: unknown };
  const name = error.name ?? '';
  const message = error.message ?? 'Unknown AWS KMS error';

  // Timeout (AbortController signal)
  if (name === 'AbortError' || message.includes('aborted')) {
    return new PluginError(
      `AWS KMS request timed out for key ${cmkId}`,
      'timeout',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Credential errors
  if (
    name === 'CredentialsProviderError' ||
    name === 'ExpiredTokenException' ||
    name === 'ExpiredToken'
  ) {
    return new PluginError(
      `AWS credential error: ${message}`,
      'credential',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Authorization errors
  if (
    name === 'AccessDeniedException' ||
    name === 'KMSAccessDeniedException' ||
    name === 'UnauthorizedAccess'
  ) {
    return new PluginError(
      `AWS KMS access denied for key ${cmkId}: ${message}`,
      'authorization',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Network / internal errors
  if (
    name === 'KMSInternalException' ||
    name === 'NetworkingError' ||
    name === 'TimeoutError' ||
    name === 'ECONNREFUSED' ||
    name === 'ENOTFOUND' ||
    message.includes('Network') ||
    message.includes('ECONNREFUSED') ||
    message.includes('ENOTFOUND') ||
    message.includes('socket')
  ) {
    return new PluginError(
      `AWS KMS network error for key ${cmkId}: ${message}`,
      'network',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Default: crypto category
  return new PluginError(
    `AWS KMS error for key ${cmkId}: ${message}`,
    'crypto',
    'aws-kms',
    cmkId,
    undefined,
    error
  );
}

/**
 * AWS KMS Provider Adapter.
 *
 * Uses the AWS SDK default credential provider chain for authentication.
 * All KMS API calls include an AbortController timeout and encryption context.
 */
export class AwsKmsAdapter implements ProviderAdapter {
  public readonly providerId = 'aws-kms';

  private readonly client: KMSClient;
  private readonly timeoutMs: number;

  constructor(client?: KMSClient, timeoutMs?: number) {
    this.client = client ?? new KMSClient({});
    this.timeoutMs = timeoutMs ?? KMS_TIMEOUT_MS;
  }

  /**
   * Generate a fresh 256-bit DEK using KMS GenerateDataKey.
   * Returns both the plaintext DEK and the wrapped (encrypted) form.
   */
  async generateDataKey(
    cmkId: string,
    context: EncryptionContext
  ): Promise<GenerateDataKeyResult> {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new GenerateDataKeyCommand({
        KeyId: cmkId,
        KeySpec: 'AES_256',
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.client.send(command, {
        abortSignal: abortController.signal,
      });

      if (!response.Plaintext || !response.CiphertextBlob) {
        throw new PluginError(
          `AWS KMS GenerateDataKey returned incomplete response for key ${cmkId}`,
          'crypto',
          'aws-kms',
          cmkId
        );
      }

      return {
        plaintextDek: new Uint8Array(response.Plaintext),
        wrappedDek: new Uint8Array(response.CiphertextBlob),
      };
    } catch (err) {
      throw mapAwsError(err, cmkId);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Wrap (encrypt) an existing DEK with the specified CMK using KMS Encrypt.
   */
  async wrapDek(
    dek: Uint8Array,
    cmkId: string,
    context: EncryptionContext
  ): Promise<Uint8Array> {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new EncryptCommand({
        KeyId: cmkId,
        Plaintext: dek,
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.client.send(command, {
        abortSignal: abortController.signal,
      });

      if (!response.CiphertextBlob) {
        throw new PluginError(
          `AWS KMS Encrypt returned no ciphertext for key ${cmkId}`,
          'crypto',
          'aws-kms',
          cmkId
        );
      }

      return new Uint8Array(response.CiphertextBlob);
    } catch (err) {
      throw mapAwsError(err, cmkId);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Unwrap (decrypt) a wrapped DEK using the specified CMK via KMS Decrypt.
   * Verifies that the returned KeyId matches the expected cmkId.
   */
  async unwrapDek(
    wrappedDek: Uint8Array,
    cmkId: string,
    context: EncryptionContext
  ): Promise<Uint8Array> {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new DecryptCommand({
        CiphertextBlob: wrappedDek,
        KeyId: cmkId,
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.client.send(command, {
        abortSignal: abortController.signal,
      });

      if (!response.Plaintext) {
        throw new PluginError(
          `AWS KMS Decrypt returned no plaintext for key ${cmkId}`,
          'crypto',
          'aws-kms',
          cmkId
        );
      }

      // Verify the returned KeyId matches the expected CMK
      if (response.KeyId && response.KeyId !== cmkId) {
        throw new PluginError(
          `AWS KMS Decrypt returned unexpected KeyId: expected ${cmkId}, got ${response.KeyId}`,
          'crypto',
          'aws-kms',
          cmkId
        );
      }

      return new Uint8Array(response.Plaintext);
    } catch (err) {
      throw mapAwsError(err, cmkId);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Validate that credentials are available and the CMK is accessible
   * by calling DescribeKey.
   */
  async validateAccess(cmkId: string): Promise<void> {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new DescribeKeyCommand({
        KeyId: cmkId,
      });

      await this.client.send(command, {
        abortSignal: abortController.signal,
      });
    } catch (err) {
      throw mapAwsError(err, cmkId);
    } finally {
      clearTimeout(timeout);
    }
  }
}
