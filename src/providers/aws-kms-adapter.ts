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
import { fromIni } from '@aws-sdk/credential-provider-ini';
import { EncryptionContext, GenerateDataKeyResult, ProviderAdapter } from '../types';
import { PluginError } from './errors';
import { KMS_TIMEOUT_MS } from '../constants';
import { extractRegionFromArn } from '../utils/arn-validator';

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

  // Key not found or invalid state
  if (
    name === 'NotFoundException' ||
    name === 'DisabledException' ||
    name === 'KMSInvalidStateException' ||
    name === 'InvalidKeyState'
  ) {
    return new PluginError(
      `AWS KMS key unavailable (${name}) for key ${cmkId}: ${message}`,
      'validation',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Invalid ARN or key ID format
  if (name === 'InvalidArnException' || name === 'ValidationException') {
    return new PluginError(
      `AWS KMS invalid key identifier ${cmkId}: ${message}`,
      'validation',
      'aws-kms',
      cmkId,
      undefined,
      error
    );
  }

  // Default: crypto category — include the original error name for debugging
  return new PluginError(
    `AWS KMS error for key ${cmkId} [${name || 'unknown'}]: ${message}`,
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

  private readonly clientFactory: (region?: string) => KMSClient;
  private readonly clientCache: Map<string, KMSClient> = new Map();
  private readonly timeoutMs: number;

  constructor(client?: KMSClient, timeoutMs?: number) {
    if (client) {
      // If an explicit client is provided (e.g. for testing), always use it
      this.clientFactory = () => client;
    } else {
      // Explicitly use fromIni() to load credentials from ~/.aws/credentials.
      // Electron (Obsidian) may not resolve the default credential chain correctly
      // because GUI apps on Windows don't always inherit shell environment variables.
      this.clientFactory = (region?: string) =>
        new KMSClient({
          ...(region ? { region } : {}),
          credentials: fromIni(),
        });
    }
    this.timeoutMs = timeoutMs ?? KMS_TIMEOUT_MS;
  }

  /**
   * Get or create a KMSClient for the region extracted from the CMK ARN.
   * Falls back to default credential chain region if ARN parsing fails.
   */
  private getClient(cmkId: string): KMSClient {
    const region = extractRegionFromArn(cmkId);
    const cacheKey = region ?? '__default__';

    let client = this.clientCache.get(cacheKey);
    if (!client) {
      client = this.clientFactory(region);
      this.clientCache.set(cacheKey, client);
    }
    return client;
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
    const timeout = window.setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new GenerateDataKeyCommand({
        KeyId: cmkId,
        KeySpec: 'AES_256',
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.getClient(cmkId).send(command, {
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
      window.clearTimeout(timeout);
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
    const timeout = window.setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new EncryptCommand({
        KeyId: cmkId,
        Plaintext: dek,
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.getClient(cmkId).send(command, {
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
      window.clearTimeout(timeout);
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
    const timeout = window.setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new DecryptCommand({
        CiphertextBlob: wrappedDek,
        KeyId: cmkId,
        EncryptionContext: toKmsEncryptionContext(context),
      });

      const response = await this.getClient(cmkId).send(command, {
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
      window.clearTimeout(timeout);
    }
  }

  /**
   * Validate that credentials are available and the CMK is accessible
   * by calling DescribeKey.
   */
  async validateAccess(cmkId: string): Promise<void> {
    const abortController = new AbortController();
    const timeout = window.setTimeout(() => abortController.abort(), this.timeoutMs);

    try {
      const command = new DescribeKeyCommand({
        KeyId: cmkId,
      });

      await this.getClient(cmkId).send(command, {
        abortSignal: abortController.signal,
      });
    } catch (err) {
      throw mapAwsError(err, cmkId);
    } finally {
      window.clearTimeout(timeout);
    }
  }
}
