/**
 * On-Disk Format parser.
 * Decodes a Uint8Array into an EncryptedFileRecord following the binary layout:
 *
 * Offset      Size        Field
 * 0           4 bytes     Magic (0x4F 0x43 0x4B 0x45 "OCKE")
 * 4           2 bytes     Version (uint16 BE)
 * 6           1 byte      ProviderIdLen
 * 7           N bytes     ProviderId (ASCII)
 * 7+N         2 bytes     CmkIdLen (uint16 BE)
 * 9+N         M bytes     CmkId (UTF-8)
 * 9+N+M       2 bytes     WrappedDekLen (uint16 BE)
 * 11+N+M      W bytes     WrappedDek
 * 11+N+M+W    12 bytes    Nonce
 * 23+N+M+W    16 bytes    AuthTag
 * 39+N+M+W    4 bytes     CiphertextLen (uint32 BE)
 * 43+N+M+W    C bytes     Ciphertext
 *
 * All multi-byte integers are big-endian.
 */

import type { EncryptedFileRecord } from '../types';
import {
  MAGIC_BYTES,
  FORMAT_VERSION,
  PROVIDER_ID_MAX_LEN,
  CMK_ID_MAX_LEN,
  WRAPPED_DEK_MAX_LEN,
  NONCE_LEN,
  AUTH_TAG_LEN,
  CIPHERTEXT_MAX_LEN,
} from '../constants';
import { PluginError } from '../providers/errors';

/** Pattern for valid provider IDs: lowercase alphanumeric + hyphens */
const PROVIDER_ID_PATTERN = /^[a-z0-9-]+$/;

/**
 * Check whether the given data starts with the OCKE magic bytes.
 * Useful for quick detection without performing a full parse.
 *
 * @param data - The byte array to check
 * @returns true if the first 4 bytes match the OCKE magic
 */
export function isMagicMatch(data: Uint8Array): boolean {
  if (data.length < MAGIC_BYTES.length) {
    return false;
  }
  for (let i = 0; i < MAGIC_BYTES.length; i++) {
    if (data[i] !== MAGIC_BYTES[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Parse a byte sequence in the On-Disk Format into an EncryptedFileRecord.
 * Validates magic bytes, version, all field lengths, and rejects trailing bytes.
 * Returns a descriptive parse error on the first invalid field.
 *
 * @param data - The binary data to parse
 * @returns A fully populated EncryptedFileRecord
 * @throws PluginError with category 'format' on any parse failure
 */
export function parse(data: Uint8Array): EncryptedFileRecord {
  let offset = 0;

  // --- Magic (4 bytes) ---
  if (data.length < offset + 4) {
    if (!isMagicMatch(data)) {
      throw new PluginError(
        'Not an encrypted file: magic bytes do not match',
        'format'
      );
    }
    throw new PluginError(
      'Truncated input: not enough bytes for magic field',
      'format'
    );
  }

  const magic = data.slice(offset, offset + 4);
  if (!isMagicMatch(data)) {
    throw new PluginError(
      'Not an encrypted file: magic bytes do not match',
      'format'
    );
  }
  offset += 4;

  // --- Version (2 bytes, uint16 BE) ---
  if (data.length < offset + 2) {
    throw new PluginError(
      'Truncated input: not enough bytes for version field',
      'format'
    );
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const version = view.getUint16(offset, false);
  offset += 2;

  if (version > FORMAT_VERSION) {
    throw new PluginError(
      `Unsupported format version: ${version} (max supported: ${FORMAT_VERSION}). Please upgrade the plugin.`,
      'format'
    );
  }

  if (version === 0) {
    throw new PluginError(
      'Invalid format version: version must be at least 1, got 0',
      'format'
    );
  }

  // --- ProviderIdLen (1 byte) ---
  if (data.length < offset + 1) {
    throw new PluginError(
      'Truncated input: not enough bytes for providerIdLen field',
      'format'
    );
  }

  const providerIdLen = data[offset];
  offset += 1;

  if (providerIdLen < 1 || providerIdLen > PROVIDER_ID_MAX_LEN) {
    throw new PluginError(
      `Invalid providerIdLen: must be 1–${PROVIDER_ID_MAX_LEN}, got ${providerIdLen}`,
      'format'
    );
  }

  // --- ProviderId (N bytes, ASCII) ---
  if (data.length < offset + providerIdLen) {
    throw new PluginError(
      'Truncated input: not enough bytes for providerId field',
      'format'
    );
  }

  const providerIdBytes = data.slice(offset, offset + providerIdLen);
  const providerId = new TextDecoder('ascii').decode(providerIdBytes);
  offset += providerIdLen;

  if (!PROVIDER_ID_PATTERN.test(providerId)) {
    throw new PluginError(
      `Invalid provider ID charset: must be lowercase alphanumeric + hyphens, got "${providerId}"`,
      'format'
    );
  }

  // --- CmkIdLen (2 bytes, uint16 BE) ---
  if (data.length < offset + 2) {
    throw new PluginError(
      'Truncated input: not enough bytes for cmkIdLen field',
      'format'
    );
  }

  const cmkIdLen = view.getUint16(offset, false);
  offset += 2;

  if (cmkIdLen < 1 || cmkIdLen > CMK_ID_MAX_LEN) {
    throw new PluginError(
      `Invalid cmkIdLen: must be 1–${CMK_ID_MAX_LEN}, got ${cmkIdLen}`,
      'format'
    );
  }

  // --- CmkId (M bytes, UTF-8) ---
  if (data.length < offset + cmkIdLen) {
    throw new PluginError(
      'Truncated input: not enough bytes for cmkId field',
      'format'
    );
  }

  const cmkIdBytes = data.slice(offset, offset + cmkIdLen);
  const cmkId = new TextDecoder('utf-8').decode(cmkIdBytes);
  offset += cmkIdLen;

  // --- WrappedDekLen (2 bytes, uint16 BE) ---
  if (data.length < offset + 2) {
    throw new PluginError(
      'Truncated input: not enough bytes for wrappedDekLen field',
      'format'
    );
  }

  const wrappedDekLen = view.getUint16(offset, false);
  offset += 2;

  if (wrappedDekLen < 1 || wrappedDekLen > WRAPPED_DEK_MAX_LEN) {
    throw new PluginError(
      `Invalid wrappedDekLen: must be 1–${WRAPPED_DEK_MAX_LEN}, got ${wrappedDekLen}`,
      'format'
    );
  }

  // --- WrappedDek (W bytes) ---
  if (data.length < offset + wrappedDekLen) {
    throw new PluginError(
      'Truncated input: not enough bytes for wrappedDek field',
      'format'
    );
  }

  const wrappedDek = data.slice(offset, offset + wrappedDekLen);
  offset += wrappedDekLen;

  // --- Nonce (12 bytes) ---
  if (data.length < offset + NONCE_LEN) {
    throw new PluginError(
      'Truncated input: not enough bytes for nonce field',
      'format'
    );
  }

  const nonce = data.slice(offset, offset + NONCE_LEN);
  offset += NONCE_LEN;

  // --- AuthTag (16 bytes) ---
  if (data.length < offset + AUTH_TAG_LEN) {
    throw new PluginError(
      'Truncated input: not enough bytes for authTag field',
      'format'
    );
  }

  const authTag = data.slice(offset, offset + AUTH_TAG_LEN);
  offset += AUTH_TAG_LEN;

  // --- CiphertextLen (4 bytes, uint32 BE) ---
  if (data.length < offset + 4) {
    throw new PluginError(
      'Truncated input: not enough bytes for ciphertextLen field',
      'format'
    );
  }

  const ciphertextLen = view.getUint32(offset, false);
  offset += 4;

  if (ciphertextLen > CIPHERTEXT_MAX_LEN) {
    throw new PluginError(
      `Invalid ciphertextLen: must be 0–${CIPHERTEXT_MAX_LEN}, got ${ciphertextLen}`,
      'format'
    );
  }

  // --- Ciphertext (C bytes) ---
  if (data.length < offset + ciphertextLen) {
    throw new PluginError(
      'Truncated input: not enough bytes for ciphertext field',
      'format'
    );
  }

  const ciphertext = data.slice(offset, offset + ciphertextLen);
  offset += ciphertextLen;

  // --- Reject trailing bytes ---
  if (offset < data.length) {
    throw new PluginError(
      `Trailing bytes: expected end of data at offset ${offset}, but ${data.length - offset} extra byte(s) remain`,
      'format'
    );
  }

  return {
    magic,
    version,
    providerId,
    cmkId,
    wrappedDek,
    nonce,
    authTag,
    ciphertext,
  };
}
