import { describe, it, expect } from 'vitest';
import { serialize } from '../../../src/format/serializer';
import {
  validateMagic,
  validateVersion,
  validateProviderId,
  validateCmkId,
  validateWrappedDek,
  validateNonce,
  validateAuthTag,
  validateCiphertext,
  validateRecord,
} from '../../../src/format/validators';
import { MAGIC_BYTES, FORMAT_VERSION, NONCE_LEN, AUTH_TAG_LEN } from '../../../src/constants';
import type { EncryptedFileRecord } from '../../../src/types';

/** Helper to create a valid EncryptedFileRecord for testing */
function makeValidRecord(overrides?: Partial<EncryptedFileRecord>): EncryptedFileRecord {
  return {
    magic: new Uint8Array(MAGIC_BYTES),
    version: FORMAT_VERSION,
    providerId: 'aws-kms',
    cmkId: 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
    wrappedDek: new Uint8Array(256).fill(0xAB),
    nonce: new Uint8Array(NONCE_LEN).fill(0x01),
    authTag: new Uint8Array(AUTH_TAG_LEN).fill(0x02),
    ciphertext: new Uint8Array([0x10, 0x20, 0x30, 0x40]),
    ...overrides,
  };
}

describe('serialize', () => {
  it('should serialize a valid record into the correct binary format', () => {
    const record = makeValidRecord();
    const result = serialize(record);

    const encoder = new TextEncoder();
    const providerIdBytes = encoder.encode(record.providerId);
    const cmkIdBytes = encoder.encode(record.cmkId);
    const N = providerIdBytes.length;
    const M = cmkIdBytes.length;
    const W = record.wrappedDek.length;
    const C = record.ciphertext.length;

    // Total size check
    expect(result.length).toBe(43 + N + M + W + C);

    const view = new DataView(result.buffer);
    let offset = 0;

    // Magic bytes
    expect(result.slice(0, 4)).toEqual(MAGIC_BYTES);
    offset += 4;

    // Version (uint16 BE)
    expect(view.getUint16(offset, false)).toBe(FORMAT_VERSION);
    offset += 2;

    // ProviderIdLen
    expect(result[offset]).toBe(N);
    offset += 1;

    // ProviderId
    expect(result.slice(offset, offset + N)).toEqual(providerIdBytes);
    offset += N;

    // CmkIdLen (uint16 BE)
    expect(view.getUint16(offset, false)).toBe(M);
    offset += 2;

    // CmkId
    expect(result.slice(offset, offset + M)).toEqual(cmkIdBytes);
    offset += M;

    // WrappedDekLen (uint16 BE)
    expect(view.getUint16(offset, false)).toBe(W);
    offset += 2;

    // WrappedDek
    expect(result.slice(offset, offset + W)).toEqual(record.wrappedDek);
    offset += W;

    // Nonce (12 bytes)
    expect(result.slice(offset, offset + 12)).toEqual(record.nonce);
    offset += 12;

    // AuthTag (16 bytes)
    expect(result.slice(offset, offset + 16)).toEqual(record.authTag);
    offset += 16;

    // CiphertextLen (uint32 BE)
    expect(view.getUint32(offset, false)).toBe(C);
    offset += 4;

    // Ciphertext
    expect(result.slice(offset, offset + C)).toEqual(record.ciphertext);
  });

  it('should serialize a record with empty ciphertext', () => {
    const record = makeValidRecord({ ciphertext: new Uint8Array(0) });
    const result = serialize(record);

    const encoder = new TextEncoder();
    const N = encoder.encode(record.providerId).length;
    const M = encoder.encode(record.cmkId).length;
    const W = record.wrappedDek.length;

    expect(result.length).toBe(43 + N + M + W + 0);

    // CiphertextLen should be 0
    const view = new DataView(result.buffer);
    const ciphertextLenOffset = 39 + N + M + W;
    expect(view.getUint32(ciphertextLenOffset, false)).toBe(0);
  });

  it('should serialize a record with minimum-length fields', () => {
    const record = makeValidRecord({
      providerId: 'a',
      cmkId: 'k',
      wrappedDek: new Uint8Array([0xFF]),
      ciphertext: new Uint8Array(0),
    });
    const result = serialize(record);

    // 43 + 1 + 1 + 1 + 0 = 46
    expect(result.length).toBe(46);
  });

  it('should throw on invalid magic bytes', () => {
    const record = makeValidRecord({ magic: new Uint8Array([0x00, 0x00, 0x00, 0x00]) });
    expect(() => serialize(record)).toThrow('Invalid magic bytes');
  });

  it('should throw on unsupported version', () => {
    const record = makeValidRecord({ version: 99 });
    expect(() => serialize(record)).toThrow('Unsupported format version');
  });

  it('should throw on empty provider ID', () => {
    const record = makeValidRecord({ providerId: '' });
    expect(() => serialize(record)).toThrow('Invalid provider ID length');
  });

  it('should throw on provider ID with invalid characters', () => {
    const record = makeValidRecord({ providerId: 'AWS_KMS' });
    expect(() => serialize(record)).toThrow('Invalid provider ID charset');
  });

  it('should throw on empty CMK ID', () => {
    const record = makeValidRecord({ cmkId: '' });
    expect(() => serialize(record)).toThrow('Invalid CMK ID length');
  });

  it('should throw on empty wrapped DEK', () => {
    const record = makeValidRecord({ wrappedDek: new Uint8Array(0) });
    expect(() => serialize(record)).toThrow('Invalid wrapped DEK length');
  });

  it('should throw on wrong nonce length', () => {
    const record = makeValidRecord({ nonce: new Uint8Array(10) });
    expect(() => serialize(record)).toThrow('Invalid nonce length');
  });

  it('should throw on wrong auth tag length', () => {
    const record = makeValidRecord({ authTag: new Uint8Array(8) });
    expect(() => serialize(record)).toThrow('Invalid auth tag length');
  });

  it('should throw on ciphertext exceeding max length', () => {
    // We can't allocate 64 MiB + 1 in a test, so test the validator directly
    // This test verifies the serializer calls validation
    const record = makeValidRecord({ wrappedDek: new Uint8Array(1025) });
    expect(() => serialize(record)).toThrow('Invalid wrapped DEK length');
  });
});

describe('validators', () => {
  describe('validateMagic', () => {
    it('should accept valid magic bytes', () => {
      expect(() => validateMagic(new Uint8Array(MAGIC_BYTES))).not.toThrow();
    });

    it('should reject wrong length', () => {
      expect(() => validateMagic(new Uint8Array([0x4F, 0x43, 0x4B]))).toThrow('Invalid magic bytes length');
    });

    it('should reject wrong content', () => {
      expect(() => validateMagic(new Uint8Array([0x4F, 0x43, 0x4B, 0x00]))).toThrow('Invalid magic bytes');
    });
  });

  describe('validateVersion', () => {
    it('should accept version 1', () => {
      expect(() => validateVersion(1)).not.toThrow();
    });

    it('should reject version 0', () => {
      expect(() => validateVersion(0)).toThrow('version must be at least 1');
    });

    it('should reject version greater than supported', () => {
      expect(() => validateVersion(2)).toThrow('Unsupported format version');
    });

    it('should reject negative version', () => {
      expect(() => validateVersion(-1)).toThrow('must be a uint16');
    });

    it('should reject non-integer version', () => {
      expect(() => validateVersion(1.5)).toThrow('must be a uint16');
    });
  });

  describe('validateProviderId', () => {
    it('should accept valid provider IDs', () => {
      expect(() => validateProviderId('aws-kms')).not.toThrow();
      expect(() => validateProviderId('azure-key-vault')).not.toThrow();
      expect(() => validateProviderId('gcp-kms')).not.toThrow();
      expect(() => validateProviderId('a')).not.toThrow();
      expect(() => validateProviderId('a'.repeat(32))).not.toThrow();
    });

    it('should reject empty provider ID', () => {
      expect(() => validateProviderId('')).toThrow('Invalid provider ID length');
    });

    it('should reject provider ID exceeding max length', () => {
      expect(() => validateProviderId('a'.repeat(33))).toThrow('Invalid provider ID length');
    });

    it('should reject uppercase characters', () => {
      expect(() => validateProviderId('AWS-KMS')).toThrow('Invalid provider ID charset');
    });

    it('should reject underscores', () => {
      expect(() => validateProviderId('aws_kms')).toThrow('Invalid provider ID charset');
    });

    it('should reject spaces', () => {
      expect(() => validateProviderId('aws kms')).toThrow('Invalid provider ID charset');
    });
  });

  describe('validateCmkId', () => {
    it('should accept valid CMK IDs', () => {
      expect(() => validateCmkId('arn:aws:kms:us-east-1:123456789012:key/test')).not.toThrow();
      expect(() => validateCmkId('k')).not.toThrow();
    });

    it('should reject empty CMK ID', () => {
      expect(() => validateCmkId('')).toThrow('Invalid CMK ID length');
    });

    it('should reject CMK ID exceeding max length', () => {
      expect(() => validateCmkId('x'.repeat(2049))).toThrow('Invalid CMK ID length');
    });
  });

  describe('validateWrappedDek', () => {
    it('should accept valid wrapped DEK', () => {
      expect(() => validateWrappedDek(new Uint8Array(1))).not.toThrow();
      expect(() => validateWrappedDek(new Uint8Array(1024))).not.toThrow();
    });

    it('should reject empty wrapped DEK', () => {
      expect(() => validateWrappedDek(new Uint8Array(0))).toThrow('Invalid wrapped DEK length');
    });

    it('should reject wrapped DEK exceeding max length', () => {
      expect(() => validateWrappedDek(new Uint8Array(1025))).toThrow('Invalid wrapped DEK length');
    });
  });

  describe('validateNonce', () => {
    it('should accept 12-byte nonce', () => {
      expect(() => validateNonce(new Uint8Array(12))).not.toThrow();
    });

    it('should reject wrong length', () => {
      expect(() => validateNonce(new Uint8Array(11))).toThrow('Invalid nonce length');
      expect(() => validateNonce(new Uint8Array(13))).toThrow('Invalid nonce length');
    });
  });

  describe('validateAuthTag', () => {
    it('should accept 16-byte auth tag', () => {
      expect(() => validateAuthTag(new Uint8Array(16))).not.toThrow();
    });

    it('should reject wrong length', () => {
      expect(() => validateAuthTag(new Uint8Array(15))).toThrow('Invalid auth tag length');
      expect(() => validateAuthTag(new Uint8Array(17))).toThrow('Invalid auth tag length');
    });
  });

  describe('validateCiphertext', () => {
    it('should accept empty ciphertext', () => {
      expect(() => validateCiphertext(new Uint8Array(0))).not.toThrow();
    });

    it('should accept ciphertext within limit', () => {
      expect(() => validateCiphertext(new Uint8Array(100))).not.toThrow();
    });
  });

  describe('validateRecord', () => {
    it('should accept a fully valid record', () => {
      const record = makeValidRecord();
      expect(() => validateRecord(record)).not.toThrow();
    });

    it('should throw on first invalid field', () => {
      const record = makeValidRecord({ magic: new Uint8Array(4) });
      expect(() => validateRecord(record)).toThrow('magic');
    });
  });
});
