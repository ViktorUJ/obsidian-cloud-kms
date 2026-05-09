/**
 * WebCrypto wrapper for AES-256-GCM operations.
 * All operations work on Uint8Array — no string intermediates.
 */

import { PluginError } from '../providers/errors';

/** AES-GCM authentication tag length in bits */
const TAG_LENGTH_BITS = 128;

/** AES-GCM authentication tag length in bytes */
const TAG_LENGTH_BYTES = 16;

/** DEK length in bytes (256-bit) */
const DEK_LENGTH_BYTES = 32;

/** Nonce length in bytes (96-bit) */
const NONCE_LENGTH_BYTES = 12;

/**
 * Result of an AES-GCM encryption operation.
 */
export interface AesGcmEncryptResult {
  /** Encrypted payload (without auth tag) */
  ciphertext: Uint8Array;
  /** 128-bit authentication tag */
  authTag: Uint8Array;
}

/**
 * Generate a fresh 256-bit (32-byte) Data Encryption Key using
 * a cryptographically secure random source.
 */
export function generateDek(): Uint8Array {
  try {
    const dek = new Uint8Array(DEK_LENGTH_BYTES);
    crypto.getRandomValues(dek);
    return dek;
  } catch (err) {
    throw new PluginError(
      'Failed to generate DEK',
      'crypto',
      undefined,
      undefined,
      undefined,
      err instanceof Error ? err : undefined
    );
  }
}

/**
 * Generate a fresh 96-bit (12-byte) nonce using
 * a cryptographically secure random source.
 */
export function generateNonce(): Uint8Array {
  try {
    const nonce = new Uint8Array(NONCE_LENGTH_BYTES);
    crypto.getRandomValues(nonce);
    return nonce;
  } catch (err) {
    throw new PluginError(
      'Failed to generate nonce',
      'crypto',
      undefined,
      undefined,
      undefined,
      err instanceof Error ? err : undefined
    );
  }
}

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param key - 32-byte AES-256 key
 * @param nonce - 12-byte nonce/IV
 * @param plaintext - Data to encrypt
 * @returns Ciphertext and 16-byte authentication tag
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
): Promise<AesGcmEncryptResult> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const result = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: TAG_LENGTH_BITS,
      },
      cryptoKey,
      plaintext
    );

    // WebCrypto returns ciphertext + authTag concatenated
    const resultBytes = new Uint8Array(result);
    const ciphertext = resultBytes.slice(0, resultBytes.length - TAG_LENGTH_BYTES);
    const authTag = resultBytes.slice(resultBytes.length - TAG_LENGTH_BYTES);

    return { ciphertext, authTag };
  } catch (err) {
    throw new PluginError(
      'AES-GCM encryption failed',
      'crypto',
      undefined,
      undefined,
      undefined,
      err instanceof Error ? err : undefined
    );
  }
}

/**
 * Decrypt ciphertext using AES-256-GCM.
 *
 * @param key - 32-byte AES-256 key
 * @param nonce - 12-byte nonce/IV used during encryption
 * @param ciphertext - Encrypted data (without auth tag)
 * @param authTag - 16-byte authentication tag
 * @returns Decrypted plaintext
 * @throws PluginError with category 'crypto' on any failure (including auth tag mismatch)
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array
): Promise<Uint8Array> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // WebCrypto expects ciphertext + authTag concatenated for decryption
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.length);

    const result = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: TAG_LENGTH_BITS,
      },
      cryptoKey,
      combined
    );

    return new Uint8Array(result);
  } catch (err) {
    throw new PluginError(
      'AES-GCM decryption failed',
      'crypto',
      undefined,
      undefined,
      undefined,
      err instanceof Error ? err : undefined
    );
  }
}
