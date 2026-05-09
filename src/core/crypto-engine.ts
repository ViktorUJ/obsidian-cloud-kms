/**
 * CryptoEngine — orchestrates envelope encryption.
 *
 * Encrypt flow:
 *   1. Get adapter from dispatcher by providerId
 *   2. Call adapter.generateDataKey(cmkId, context) → plaintextDek + wrappedDek
 *   3. Generate nonce via generateNonce()
 *   4. AES-256-GCM encrypt plaintext → ciphertext + authTag
 *   5. Zero plaintextDek immediately after encryption
 *   6. Return EncryptedFileRecord with MAGIC_BYTES, FORMAT_VERSION, etc.
 *   7. On any error: zero plaintextDek (if generated), re-throw
 *
 * Decrypt flow:
 *   1. Get adapter from dispatcher by record.providerId
 *   2. Call adapter.unwrapDek(wrappedDek, cmkId, context) → plaintextDek
 *   3. AES-256-GCM decrypt ciphertext using nonce + authTag → plaintext
 *   4. Zero plaintextDek immediately after decryption
 *   5. Return plaintext
 *   6. On any error: zero plaintextDek (if unwrapped), re-throw
 */

import type {
  CryptoEngine,
  EncryptedFileRecord,
  EncryptionContext,
  ProviderDispatcher,
} from '../types';
import { MAGIC_BYTES, FORMAT_VERSION } from '../constants';
import { generateNonce, aesGcmEncrypt, aesGcmDecrypt } from './webcrypto';

/**
 * Zero-fill a Uint8Array in place.
 * Uses random fill then zero fill to defeat dead-store elimination.
 */
function zeroDek(dek: Uint8Array): void {
  crypto.getRandomValues(dek);
  dek.fill(0);
}

/**
 * Implementation of the CryptoEngine interface.
 * Orchestrates DEK generation, AES-256-GCM encrypt/decrypt,
 * and provider dispatch for wrap/unwrap operations.
 */
export class CryptoEngineImpl implements CryptoEngine {
  constructor(private readonly dispatcher: ProviderDispatcher) {}

  /**
   * Encrypt plaintext using envelope encryption.
   *
   * Generates a DEK via the provider adapter, encrypts locally with AES-256-GCM,
   * and returns a complete EncryptedFileRecord ready for serialization.
   *
   * The DEK is always zeroed after use, whether the operation succeeds or fails.
   */
  async encrypt(
    plaintext: Uint8Array,
    cmkId: string,
    providerId: string,
    context: EncryptionContext
  ): Promise<EncryptedFileRecord> {
    let plaintextDek: Uint8Array | null = null;

    try {
      // 1. Get adapter from dispatcher
      const adapter = this.dispatcher.getAdapter(providerId);

      // 2. Generate DEK via provider (returns plaintext + wrapped forms)
      const dataKeyResult = await adapter.generateDataKey(cmkId, context);
      plaintextDek = dataKeyResult.plaintextDek;
      const wrappedDek = dataKeyResult.wrappedDek;

      // 3. Generate nonce
      const nonce = generateNonce();

      // 4. AES-256-GCM encrypt
      const { ciphertext, authTag } = await aesGcmEncrypt(
        plaintextDek,
        nonce,
        plaintext
      );

      // 5. Zero DEK immediately after encryption
      zeroDek(plaintextDek);
      plaintextDek = null;

      // 6. Return EncryptedFileRecord
      return {
        magic: new Uint8Array(MAGIC_BYTES),
        version: FORMAT_VERSION,
        providerId,
        cmkId,
        wrappedDek,
        nonce,
        authTag,
        ciphertext,
      };
    } catch (err) {
      // 7. On any error: zero DEK if generated, re-throw
      if (plaintextDek) {
        zeroDek(plaintextDek);
      }
      throw err;
    }
  }

  /**
   * Decrypt an EncryptedFileRecord back to plaintext.
   *
   * Unwraps the DEK via the provider adapter, decrypts locally with AES-256-GCM,
   * and verifies the authentication tag.
   *
   * The DEK is always zeroed after use, whether the operation succeeds or fails.
   */
  async decrypt(
    record: EncryptedFileRecord,
    context: EncryptionContext
  ): Promise<Uint8Array> {
    let plaintextDek: Uint8Array | null = null;

    try {
      // 1. Get adapter from dispatcher
      const adapter = this.dispatcher.getAdapter(record.providerId);

      // 2. Unwrap DEK via provider
      plaintextDek = await adapter.unwrapDek(
        record.wrappedDek,
        record.cmkId,
        context
      );

      // 3. AES-256-GCM decrypt (auth tag verification happens inside)
      const plaintext = await aesGcmDecrypt(
        plaintextDek,
        record.nonce,
        record.ciphertext,
        record.authTag
      );

      // 4. Zero DEK immediately after decryption
      zeroDek(plaintextDek);
      plaintextDek = null;

      // 5. Return plaintext
      return plaintext;
    } catch (err) {
      // 6. On any error: zero DEK if unwrapped, re-throw
      if (plaintextDek) {
        zeroDek(plaintextDek);
      }
      throw err;
    }
  }
}
