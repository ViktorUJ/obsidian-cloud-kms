/**
 * Unit tests for the WebCrypto wrapper (src/core/webcrypto.ts).
 * Validates: Requirements 13.1, 17.2, 1.2, 1.4
 */

import { describe, it, expect } from 'vitest';
import {
  generateDek,
  generateNonce,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from '../../../src/core/webcrypto';

describe('WebCrypto wrapper', () => {
  describe('generateDek', () => {
    it('should return 32 bytes', () => {
      const dek = generateDek();
      expect(dek).toBeInstanceOf(Uint8Array);
      expect(dek.length).toBe(32);
    });

    it('should return different values on successive calls', () => {
      const dek1 = generateDek();
      const dek2 = generateDek();
      // Extremely unlikely to be equal for 32 random bytes
      expect(dek1).not.toEqual(dek2);
    });
  });

  describe('generateNonce', () => {
    it('should return 12 bytes', () => {
      const nonce = generateNonce();
      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(12);
    });

    it('should return different values on successive calls', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toEqual(nonce2);
    });
  });

  describe('aesGcmEncrypt', () => {
    it('should return ciphertext and a 16-byte authTag', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Hello, World!');

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);

      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(authTag).toBeInstanceOf(Uint8Array);
      expect(authTag.length).toBe(16);
      // Ciphertext length equals plaintext length for AES-GCM (stream cipher)
      expect(ciphertext.length).toBe(plaintext.length);
    });

    it('should produce different ciphertext for different nonces', async () => {
      const key = generateDek();
      const plaintext = new TextEncoder().encode('Same plaintext');

      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      const result1 = await aesGcmEncrypt(key, nonce1, plaintext);
      const result2 = await aesGcmEncrypt(key, nonce2, plaintext);

      expect(result1.ciphertext).not.toEqual(result2.ciphertext);
    });

    it('should handle empty plaintext', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new Uint8Array(0);

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);

      expect(ciphertext.length).toBe(0);
      expect(authTag.length).toBe(16);
    });
  });

  describe('aesGcmDecrypt', () => {
    it('should round-trip encrypt then decrypt', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Secret message for round-trip test');

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);
      const decrypted = await aesGcmDecrypt(key, nonce, ciphertext, authTag);

      expect(decrypted).toEqual(plaintext);
    });

    it('should round-trip empty plaintext', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new Uint8Array(0);

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);
      const decrypted = await aesGcmDecrypt(key, nonce, ciphertext, authTag);

      expect(decrypted).toEqual(plaintext);
    });

    it('should throw PluginError on tampered ciphertext', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Tamper test');

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);

      // Flip a byte in the ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0xff;

      await expect(
        aesGcmDecrypt(key, nonce, tampered, authTag)
      ).rejects.toThrow('AES-GCM decryption failed');
    });

    it('should throw PluginError on tampered authTag', async () => {
      const key = generateDek();
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Auth tag tamper test');

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);

      // Flip a byte in the auth tag
      const tamperedTag = new Uint8Array(authTag);
      tamperedTag[0] ^= 0xff;

      await expect(
        aesGcmDecrypt(key, nonce, ciphertext, tamperedTag)
      ).rejects.toThrow('AES-GCM decryption failed');
    });

    it('should throw PluginError with wrong key', async () => {
      const key = generateDek();
      const wrongKey = generateDek();
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Wrong key test');

      const { ciphertext, authTag } = await aesGcmEncrypt(key, nonce, plaintext);

      await expect(
        aesGcmDecrypt(wrongKey, nonce, ciphertext, authTag)
      ).rejects.toThrow('AES-GCM decryption failed');
    });
  });
});
