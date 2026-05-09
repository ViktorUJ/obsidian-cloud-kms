/**
 * On-Disk Format serializer.
 * Encodes an EncryptedFileRecord into a Uint8Array following the binary layout:
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
import { validateRecord } from './validators';

/**
 * Serialize an EncryptedFileRecord into the On-Disk Format byte sequence.
 * Validates all field constraints before serialization.
 * Throws PluginError with category 'format' on any constraint violation.
 */
export function serialize(record: EncryptedFileRecord): Uint8Array {
  // Validate all fields before producing output
  validateRecord(record);

  const encoder = new TextEncoder();
  const providerIdBytes = encoder.encode(record.providerId);
  const cmkIdBytes = encoder.encode(record.cmkId);

  const N = providerIdBytes.length;
  const M = cmkIdBytes.length;
  const W = record.wrappedDek.length;
  const C = record.ciphertext.length;

  // Total size: 4 (magic) + 2 (version) + 1 (providerIdLen) + N + 2 (cmkIdLen) + M
  //           + 2 (wrappedDekLen) + W + 12 (nonce) + 16 (authTag) + 4 (ciphertextLen) + C
  const totalSize = 43 + N + M + W + C;
  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);

  let offset = 0;

  // Magic (4 bytes)
  buffer.set(record.magic, offset);
  offset += 4;

  // Version (uint16 BE)
  view.setUint16(offset, record.version, false);
  offset += 2;

  // ProviderIdLen (1 byte)
  buffer[offset] = N;
  offset += 1;

  // ProviderId (N bytes, ASCII)
  buffer.set(providerIdBytes, offset);
  offset += N;

  // CmkIdLen (uint16 BE)
  view.setUint16(offset, M, false);
  offset += 2;

  // CmkId (M bytes, UTF-8)
  buffer.set(cmkIdBytes, offset);
  offset += M;

  // WrappedDekLen (uint16 BE)
  view.setUint16(offset, W, false);
  offset += 2;

  // WrappedDek (W bytes)
  buffer.set(record.wrappedDek, offset);
  offset += W;

  // Nonce (12 bytes)
  buffer.set(record.nonce, offset);
  offset += 12;

  // AuthTag (16 bytes)
  buffer.set(record.authTag, offset);
  offset += 16;

  // CiphertextLen (uint32 BE)
  view.setUint32(offset, C, false);
  offset += 4;

  // Ciphertext (C bytes)
  buffer.set(record.ciphertext, offset);

  return buffer;
}
