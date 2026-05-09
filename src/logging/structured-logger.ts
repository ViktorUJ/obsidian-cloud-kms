/**
 * Structured logger for the obsidian-cloud-kms-encryption plugin.
 *
 * Emits structured JSON log entries to console.log (info) and console.error (error)
 * with timestamp, provider, cmkId, filePath, payload size, and other metadata.
 *
 * All log entries are sanitized before emission to ensure no sensitive data
 * (plaintext, DEK, credentials) is ever logged.
 *
 * Requirements: 15.3, 15.4, 15.5, 15.6
 */

import { sanitizeLogPayload } from './sanitizer';

/**
 * Log levels supported by the structured logger.
 */
export type LogLevel = 'info' | 'error';

/**
 * Structured log entry emitted by the logger.
 */
export interface LogEntry {
  level: LogLevel;
  timestamp: string;
  providerId: string;
  cmkId: string;
  filePath: string;
  payloadByteLength?: number;
  formatVersion?: number;
  errorCode?: string;
  message: string;
}

/**
 * Parameters for logging an encryption event.
 */
export interface LogEncryptParams {
  providerId: string;
  cmkId: string;
  filePath: string;
  payloadByteLength: number;
}

/**
 * Parameters for logging a decryption event.
 */
export interface LogDecryptParams {
  providerId: string;
  cmkId: string;
  filePath: string;
  formatVersion: number;
}

/**
 * Parameters for logging an error event.
 */
export interface LogErrorParams {
  providerId: string;
  cmkId: string;
  filePath: string;
  errorCode: string;
  message: string;
}

/**
 * Emit a structured log entry as a JSON string.
 * Info-level entries go to console.log, error-level to console.error.
 */
function emit(entry: LogEntry): void {
  const sanitized = sanitizeLogPayload(entry as unknown as Record<string, unknown>);
  const json = JSON.stringify(sanitized);

  if (entry.level === 'error') {
    console.error(json);
  } else {
    console.log(json);
  }
}

/**
 * Get the current timestamp in ISO-8601 UTC format.
 */
function utcTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Log a successful encryption event.
 *
 * Emits a structured info-level log entry containing the provider identifier,
 * CMK identifier, vault-relative file path, encrypted payload byte length,
 * and a timestamp in ISO-8601 UTC.
 *
 * Requirement 15.3
 */
export function logEncrypt(params: LogEncryptParams): void {
  const entry: LogEntry = {
    level: 'info',
    timestamp: utcTimestamp(),
    providerId: params.providerId,
    cmkId: params.cmkId,
    filePath: params.filePath,
    payloadByteLength: params.payloadByteLength,
    message: 'File encrypted successfully',
  };
  emit(entry);
}

/**
 * Log a successful decryption event.
 *
 * Emits a structured info-level log entry containing the provider identifier,
 * CMK identifier, vault-relative file path, on-disk format version,
 * and a timestamp in ISO-8601 UTC.
 *
 * Requirement 15.4
 */
export function logDecrypt(params: LogDecryptParams): void {
  const entry: LogEntry = {
    level: 'info',
    timestamp: utcTimestamp(),
    providerId: params.providerId,
    cmkId: params.cmkId,
    filePath: params.filePath,
    formatVersion: params.formatVersion,
    message: 'File decrypted successfully',
  };
  emit(entry);
}

/**
 * Log a KMS operation error.
 *
 * Emits a structured error-level log entry containing the provider identifier,
 * CMK identifier, vault-relative file path, provider error code or category,
 * and a timestamp in ISO-8601 UTC.
 *
 * Requirement 15.5
 */
export function logError(params: LogErrorParams): void {
  const entry: LogEntry = {
    level: 'error',
    timestamp: utcTimestamp(),
    providerId: params.providerId,
    cmkId: params.cmkId,
    filePath: params.filePath,
    errorCode: params.errorCode,
    message: params.message,
  };
  emit(entry);
}
