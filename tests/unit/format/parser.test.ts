import { describe, it, expect } from 'vitest';
import { parse, isMagicMatch } from '../../../src/format/parser';
import { serialize } from '../../../src/format/serializer';
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

/** Helper to serialize a valid record for parser tests */
function makeValidBytes(overrides?: Partial<EncryptedFileRecord>): Uint8Array {
  return serialize(makeValidRecord(overrides));
}

describe('isMagicMatch', () => {
  it('should return true for data starting with OCKE magic bytes', () => {
    const data = new Uint8Array([0x4F, 0x43, 0x4B, 0x45, 0x00, 0x01]);
    expect(isMagicMatch(data)).toBe(true);
  });

  it('should return false for data with wrong magic bytes', () => {
    const data = new Uint8Array([0x00, 0x43, 0x4B, 0x45, 0x00, 0x01]);
    expect(isMagicMatch(data)).toBe(false);
  });

  it('should return false for data shorter than 4 bytes', () => {
    const data = new Uint8Array([0x4F, 0x43, 0x4B]);
    expect(isMagicMatch(data)).toBe(false);
  });

  it('should return false for empty data', () => {
    expect(isMagicMatch(new Uint8Array(0))).toBe(false);
  });
});

describe('parse', () => {
  it('should parse a valid serialized record', () => {
    const original = makeValidRecord();
    const bytes = serialize(original);
    const parsed = parse(bytes);

    expect(parsed.magic).toEqual(original.magic);
    expect(parsed.version).toBe(original.version);
    expect(parsed.providerId).toBe(original.providerId);
    expect(parsed.cmkId).toBe(original.cmkId);
    expect(parsed.wrappedDek).toEqual(original.wrappedDek);
    expect(parsed.nonce).toEqual(original.nonce);
    expect(parsed.authTag).toEqual(original.authTag);
    expect(parsed.ciphertext).toEqual(original.ciphertext);
  });

  it('should parse a record with empty ciphertext', () => {
    const original = makeValidRecord({ ciphertext: new Uint8Array(0) });
    const bytes = serialize(original);
    const parsed = parse(bytes);

    expect(parsed.ciphertext).toEqual(new Uint8Array(0));
    expect(parsed.providerId).toBe('aws-kms');
  });

  it('should parse a record with minimum-length fields', () => {
    const original = makeValidRecord({
      providerId: 'a',
      cmkId: 'k',
      wrappedDek: new Uint8Array([0xFF]),
      ciphertext: new Uint8Array(0),
    });
    const bytes = serialize(original);
    const parsed = parse(bytes);

    expect(parsed.providerId).toBe('a');
    expect(parsed.cmkId).toBe('k');
    expect(parsed.wrappedDek).toEqual(new Uint8Array([0xFF]));
  });

  describe('magic bytes validation', () => {
    it('should throw "not encrypted" error for wrong magic bytes', () => {
      const bytes = makeValidBytes();
      bytes[0] = 0x00; // corrupt magic
      expect(() => parse(bytes)).toThrow('Not an encrypted file');
    });

    it('should throw "not encrypted" error for completely different data', () => {
      const data = new Uint8Array([0x50, 0x4B, 0x03, 0x04]); // ZIP magic
      expect(() => parse(data)).toThrow('Not an encrypted file');
    });

    it('should throw for empty input', () => {
      expect(() => parse(new Uint8Array(0))).toThrow('Not an encrypted file');
    });
  });

  describe('version validation', () => {
    it('should throw "unsupported version" for version > FORMAT_VERSION', () => {
      const bytes = makeValidBytes();
      // Version is at offset 4, uint16 BE
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(4, 99, false);
      expect(() => parse(bytes)).toThrow('Unsupported format version');
      expect(() => parse(bytes)).toThrow('upgrade');
    });

    it('should throw for version 0', () => {
      const bytes = makeValidBytes();
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(4, 0, false);
      expect(() => parse(bytes)).toThrow('version must be at least 1');
    });
  });

  describe('providerIdLen validation', () => {
    it('should throw for providerIdLen of 0', () => {
      const bytes = makeValidBytes();
      bytes[6] = 0; // providerIdLen = 0
      expect(() => parse(bytes)).toThrow('Invalid providerIdLen');
    });

    it('should throw for providerIdLen > 32', () => {
      const bytes = makeValidBytes();
      bytes[6] = 33; // providerIdLen = 33
      expect(() => parse(bytes)).toThrow('Invalid providerIdLen');
    });
  });

  describe('providerId charset validation', () => {
    it('should throw for uppercase characters in providerId', () => {
      // Build a record with uppercase provider ID manually
      const record = makeValidRecord({ providerId: 'aws-kms' });
      const bytes = serialize(record);
      // Overwrite the providerId bytes with uppercase
      bytes[7] = 0x41; // 'A'
      expect(() => parse(bytes)).toThrow('Invalid provider ID charset');
    });
  });

  describe('cmkIdLen validation', () => {
    it('should throw for cmkIdLen of 0', () => {
      const bytes = makeValidBytes();
      const providerIdLen = bytes[6];
      const cmkIdLenOffset = 7 + providerIdLen;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(cmkIdLenOffset, 0, false);
      expect(() => parse(bytes)).toThrow('Invalid cmkIdLen');
    });

    it('should throw for cmkIdLen > 2048', () => {
      const bytes = makeValidBytes();
      const providerIdLen = bytes[6];
      const cmkIdLenOffset = 7 + providerIdLen;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(cmkIdLenOffset, 2049, false);
      expect(() => parse(bytes)).toThrow('Invalid cmkIdLen');
    });
  });

  describe('wrappedDekLen validation', () => {
    it('should throw for wrappedDekLen of 0', () => {
      const record = makeValidRecord();
      const bytes = serialize(record);
      const providerIdLen = bytes[6];
      const encoder = new TextEncoder();
      const cmkIdLen = encoder.encode(record.cmkId).length;
      const wrappedDekLenOffset = 9 + providerIdLen + cmkIdLen;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(wrappedDekLenOffset, 0, false);
      expect(() => parse(bytes)).toThrow('Invalid wrappedDekLen');
    });

    it('should throw for wrappedDekLen > 1024', () => {
      const record = makeValidRecord();
      const bytes = serialize(record);
      const providerIdLen = bytes[6];
      const encoder = new TextEncoder();
      const cmkIdLen = encoder.encode(record.cmkId).length;
      const wrappedDekLenOffset = 9 + providerIdLen + cmkIdLen;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint16(wrappedDekLenOffset, 1025, false);
      expect(() => parse(bytes)).toThrow('Invalid wrappedDekLen');
    });
  });

  describe('ciphertextLen validation', () => {
    it('should throw for ciphertextLen > 67108864', () => {
      const record = makeValidRecord();
      const bytes = serialize(record);
      const providerIdLen = bytes[6];
      const encoder = new TextEncoder();
      const cmkIdLen = encoder.encode(record.cmkId).length;
      const wrappedDekLen = record.wrappedDek.length;
      const ciphertextLenOffset = 39 + providerIdLen + cmkIdLen + wrappedDekLen;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      view.setUint32(ciphertextLenOffset, 67_108_865, false);
      expect(() => parse(bytes)).toThrow('Invalid ciphertextLen');
    });
  });

  describe('truncation errors', () => {
    it('should throw truncated error when input is too short for version', () => {
      // Only magic bytes, no version
      const data = new Uint8Array([0x4F, 0x43, 0x4B, 0x45]);
      expect(() => parse(data)).toThrow('Truncated input');
      expect(() => parse(data)).toThrow('version');
    });

    it('should throw truncated error when input is too short for providerIdLen', () => {
      // Magic + version, but no providerIdLen
      const data = new Uint8Array([0x4F, 0x43, 0x4B, 0x45, 0x00, 0x01]);
      expect(() => parse(data)).toThrow('Truncated input');
      expect(() => parse(data)).toThrow('providerIdLen');
    });

    it('should throw truncated error when input is too short for providerId', () => {
      // Magic + version + providerIdLen=7, but only 2 bytes of providerId
      const data = new Uint8Array([0x4F, 0x43, 0x4B, 0x45, 0x00, 0x01, 0x07, 0x61, 0x62]);
      expect(() => parse(data)).toThrow('Truncated input');
      expect(() => parse(data)).toThrow('providerId');
    });

    it('should throw truncated error when input is too short for cmkIdLen', () => {
      // Magic + version + providerIdLen=1 + providerId('a') but no cmkIdLen
      const data = new Uint8Array([0x4F, 0x43, 0x4B, 0x45, 0x00, 0x01, 0x01, 0x61]);
      expect(() => parse(data)).toThrow('Truncated input');
      expect(() => parse(data)).toThrow('cmkIdLen');
    });

    it('should throw truncated error when input is too short for nonce', () => {
      // Build a valid record, then truncate before nonce completes
      const bytes = makeValidBytes();
      const providerIdLen = bytes[6];
      const encoder = new TextEncoder();
      const record = makeValidRecord();
      const cmkIdLen = encoder.encode(record.cmkId).length;
      const wrappedDekLen = record.wrappedDek.length;
      // Nonce starts at 11 + providerIdLen + cmkIdLen + wrappedDekLen
      const nonceStart = 11 + providerIdLen + cmkIdLen + wrappedDekLen;
      const truncated = bytes.slice(0, nonceStart + 5); // only 5 of 12 nonce bytes
      expect(() => parse(truncated)).toThrow('Truncated input');
      expect(() => parse(truncated)).toThrow('nonce');
    });

    it('should throw truncated error when input is too short for ciphertext', () => {
      const bytes = makeValidBytes();
      // Truncate the last byte of ciphertext
      const truncated = bytes.slice(0, bytes.length - 1);
      expect(() => parse(truncated)).toThrow('Truncated input');
      expect(() => parse(truncated)).toThrow('ciphertext');
    });
  });

  describe('trailing bytes', () => {
    it('should throw trailing bytes error when extra data exists after ciphertext', () => {
      const bytes = makeValidBytes();
      const withTrailing = new Uint8Array(bytes.length + 3);
      withTrailing.set(bytes);
      withTrailing[bytes.length] = 0xFF;
      withTrailing[bytes.length + 1] = 0xFE;
      withTrailing[bytes.length + 2] = 0xFD;
      expect(() => parse(withTrailing)).toThrow('Trailing bytes');
      expect(() => parse(withTrailing)).toThrow('3 extra byte(s)');
    });

    it('should throw trailing bytes error for single extra byte', () => {
      const bytes = makeValidBytes();
      const withTrailing = new Uint8Array(bytes.length + 1);
      withTrailing.set(bytes);
      withTrailing[bytes.length] = 0x00;
      expect(() => parse(withTrailing)).toThrow('Trailing bytes');
      expect(() => parse(withTrailing)).toThrow('1 extra byte(s)');
    });
  });

  describe('error type', () => {
    it('should throw PluginError with category format', () => {
      try {
        parse(new Uint8Array([0x00, 0x00, 0x00, 0x00]));
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.name).toBe('PluginError');
        expect(err.category).toBe('format');
      }
    });
  });

  describe('round-trip with serializer', () => {
    it('should round-trip a record with various field sizes', () => {
      const records = [
        makeValidRecord(),
        makeValidRecord({ providerId: 'gcp-kms', cmkId: 'projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key' }),
        makeValidRecord({ wrappedDek: new Uint8Array(512).fill(0xCC) }),
        makeValidRecord({ ciphertext: new Uint8Array(1000).fill(0xDD) }),
      ];

      for (const original of records) {
        const bytes = serialize(original);
        const parsed = parse(bytes);
        expect(parsed.magic).toEqual(original.magic);
        expect(parsed.version).toBe(original.version);
        expect(parsed.providerId).toBe(original.providerId);
        expect(parsed.cmkId).toBe(original.cmkId);
        expect(parsed.wrappedDek).toEqual(original.wrappedDek);
        expect(parsed.nonce).toEqual(original.nonce);
        expect(parsed.authTag).toEqual(original.authTag);
        expect(parsed.ciphertext).toEqual(original.ciphertext);
      }
    });
  });
});
