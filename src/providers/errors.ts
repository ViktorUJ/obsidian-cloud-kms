/**
 * Error types for the obsidian-cloud-kms-encryption plugin.
 */

/**
 * Error category classification for structured error handling.
 */
export type ErrorCategory =
  | 'credential'
  | 'authorization'
  | 'network'
  | 'timeout'
  | 'integrity'
  | 'format'
  | 'validation'
  | 'crypto'
  | 'size-limit';

/**
 * Base error class for all plugin errors.
 * Carries structured metadata for logging without leaking sensitive data.
 */
export class PluginError extends Error {
  public readonly name = 'PluginError';

  constructor(
    message: string,
    public readonly category: ErrorCategory,
    public readonly providerId?: string,
    public readonly cmkId?: string,
    public readonly filePath?: string,
    public readonly cause?: Error
  ) {
    super(message);
  }
}
