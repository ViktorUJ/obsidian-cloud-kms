/**
 * Field constraint validators for the On-Disk Format.
 * Each validator throws a PluginError with category 'format' on violation.
 */

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
 * Validate that magic bytes match the expected OCKE header.
 */
export function validateMagic(magic: Uint8Array): void {
  if (magic.length !== MAGIC_BYTES.length) {
    throw new PluginError(
      `Invalid magic bytes length: expected ${MAGIC_BYTES.length}, got ${magic.length}`,
      'format'
    );
  }
  for (let i = 0; i < MAGIC_BYTES.length; i++) {
    if (magic[i] !== MAGIC_BYTES[i]) {
      throw new PluginError(
        `Invalid magic bytes: expected 0x${MAGIC_BYTES[i].toString(16).padStart(2, '0')} at offset ${i}, got 0x${magic[i].toString(16).padStart(2, '0')}`,
        'format'
      );
    }
  }
}

/**
 * Validate that the format version is supported.
 */
export function validateVersion(version: number): void {
  if (!Number.isInteger(version) || version < 0 || version > 0xFFFF) {
    throw new PluginError(
      `Invalid format version: must be a uint16, got ${version}`,
      'format'
    );
  }
  if (version > FORMAT_VERSION) {
    throw new PluginError(
      `Unsupported format version: ${version} (max supported: ${FORMAT_VERSION})`,
      'format'
    );
  }
  if (version === 0) {
    throw new PluginError(
      `Invalid format version: version must be at least 1, got 0`,
      'format'
    );
  }
}

/**
 * Validate provider ID length and charset constraints.
 */
export function validateProviderId(providerId: string): void {
  const len = providerId.length;
  if (len < 1 || len > PROVIDER_ID_MAX_LEN) {
    throw new PluginError(
      `Invalid provider ID length: must be 1–${PROVIDER_ID_MAX_LEN}, got ${len}`,
      'format'
    );
  }
  if (!PROVIDER_ID_PATTERN.test(providerId)) {
    throw new PluginError(
      `Invalid provider ID charset: must be lowercase alphanumeric + hyphens, got "${providerId}"`,
      'format'
    );
  }
}

/**
 * Validate CMK ID length constraint.
 */
export function validateCmkId(cmkId: string): void {
  const encoded = new TextEncoder().encode(cmkId);
  if (encoded.length < 1 || encoded.length > CMK_ID_MAX_LEN) {
    throw new PluginError(
      `Invalid CMK ID length: must be 1–${CMK_ID_MAX_LEN} bytes, got ${encoded.length}`,
      'format'
    );
  }
}

/**
 * Validate wrapped DEK length constraint.
 */
export function validateWrappedDek(wrappedDek: Uint8Array): void {
  if (wrappedDek.length < 1 || wrappedDek.length > WRAPPED_DEK_MAX_LEN) {
    throw new PluginError(
      `Invalid wrapped DEK length: must be 1–${WRAPPED_DEK_MAX_LEN}, got ${wrappedDek.length}`,
      'format'
    );
  }
}

/**
 * Validate nonce is exactly the required length.
 */
export function validateNonce(nonce: Uint8Array): void {
  if (nonce.length !== NONCE_LEN) {
    throw new PluginError(
      `Invalid nonce length: must be exactly ${NONCE_LEN}, got ${nonce.length}`,
      'format'
    );
  }
}

/**
 * Validate auth tag is exactly the required length.
 */
export function validateAuthTag(authTag: Uint8Array): void {
  if (authTag.length !== AUTH_TAG_LEN) {
    throw new PluginError(
      `Invalid auth tag length: must be exactly ${AUTH_TAG_LEN}, got ${authTag.length}`,
      'format'
    );
  }
}

/**
 * Validate ciphertext length constraint.
 */
export function validateCiphertext(ciphertext: Uint8Array): void {
  if (ciphertext.length > CIPHERTEXT_MAX_LEN) {
    throw new PluginError(
      `Invalid ciphertext length: must be 0–${CIPHERTEXT_MAX_LEN}, got ${ciphertext.length}`,
      'format'
    );
  }
}

/**
 * Validate all fields of an EncryptedFileRecord.
 * Throws on the first constraint violation encountered.
 */
export function validateRecord(record: {
  magic: Uint8Array;
  version: number;
  providerId: string;
  cmkId: string;
  wrappedDek: Uint8Array;
  nonce: Uint8Array;
  authTag: Uint8Array;
  ciphertext: Uint8Array;
}): void {
  validateMagic(record.magic);
  validateVersion(record.version);
  validateProviderId(record.providerId);
  validateCmkId(record.cmkId);
  validateWrappedDek(record.wrappedDek);
  validateNonce(record.nonce);
  validateAuthTag(record.authTag);
  validateCiphertext(record.ciphertext);
}
