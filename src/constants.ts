/**
 * Shared constants for the obsidian-cloud-kms-encryption plugin.
 */

/** Magic bytes identifying an OCKE encrypted file: "OCKE" in ASCII */
export const MAGIC_BYTES = new Uint8Array([0x4F, 0x43, 0x4B, 0x45]);

/** Current on-disk format version */
export const FORMAT_VERSION = 1;

/** Maximum length of the provider ID field (bytes/chars) */
export const PROVIDER_ID_MAX_LEN = 32;

/** Maximum length of the CMK ID field (bytes) */
export const CMK_ID_MAX_LEN = 2048;

/** Maximum length of the wrapped DEK field (bytes) */
export const WRAPPED_DEK_MAX_LEN = 1024;

/** Fixed nonce length for AES-256-GCM (bytes) */
export const NONCE_LEN = 12;

/** Fixed authentication tag length for AES-256-GCM (bytes) */
export const AUTH_TAG_LEN = 16;

/** Maximum ciphertext length: 64 MiB */
export const CIPHERTEXT_MAX_LEN = 67_108_864;

/** Default timeout for KMS API calls (ms) */
export const KMS_TIMEOUT_MS = 10_000;

/** Timeout for file-level encryption KMS calls (ms) */
export const KMS_FILE_TIMEOUT_MS = 30_000;

/** Duration for Obsidian notice display (ms) */
export const NOTICE_DURATION_MS = 5_000;

/** Maximum selection size for manual encrypt/decrypt commands (chars) */
export const MAX_SELECTION_CHARS = 1_048_576;

/** Maximum attachment file size for decryption (bytes): 50 MB */
export const MAX_ATTACHMENT_SIZE = 52_428_800;

/** Default suffix for encrypted notes */
export const ENCRYPTED_NOTE_SUFFIX_DEFAULT = ".secret.md";

/** Maximum length of the encrypted note suffix setting (chars) */
export const ENCRYPTED_NOTE_SUFFIX_MAX_LEN = 64;
