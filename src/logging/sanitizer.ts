/**
 * Log payload sanitizer for the obsidian-cloud-kms-encryption plugin.
 *
 * Ensures no sensitive data (plaintext content, DEK bytes, wrapped DEK bytes,
 * auth tag bytes, or credential material) appears in any log entry.
 *
 * Requirements: 15.6
 */

/**
 * Known credential-related field names that must never appear in logs.
 */
const SENSITIVE_FIELD_NAMES: ReadonlySet<string> = new Set([
  'plaintextDek',
  'dek',
  'wrappedDek',
  'authTag',
  'ciphertext',
  'plaintext',
  'secretKey',
  'accessKey',
  'sessionToken',
  'password',
  'credential',
  'credentials',
  'token',
  'secret',
  'privateKey',
]);

/**
 * Known credential patterns that must be redacted from string values.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  // AWS access key IDs
  /AKIA[0-9A-Z]{16}/g,
  // AWS secret keys (base64-like, 40 chars)
  /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])/g,
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
];

/**
 * Sanitize a value for safe inclusion in log output.
 * Strips Uint8Array content, credential strings, and sensitive field values.
 *
 * @param value - Any value to sanitize
 * @param fieldName - Optional field name for context-aware sanitization
 * @returns A sanitized version safe for logging
 */
export function sanitizeValue(value: unknown, fieldName?: string): unknown {
  // Check if the field name itself is sensitive
  if (fieldName && SENSITIVE_FIELD_NAMES.has(fieldName)) {
    return '[REDACTED]';
  }

  // Uint8Array content must never appear in logs
  if (value instanceof Uint8Array) {
    return '[REDACTED binary data]';
  }

  // ArrayBuffer content must never appear in logs
  if (value instanceof ArrayBuffer) {
    return '[REDACTED binary data]';
  }

  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }

  if (value !== null && typeof value === 'object') {
    return sanitizeObject(value as Record<string, unknown>);
  }

  return value;
}

/**
 * Sanitize a string value by redacting credential patterns.
 */
function sanitizeString(value: string): string {
  let result = value;
  for (const pattern of CREDENTIAL_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

/**
 * Sanitize an object by recursively checking all fields.
 */
function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = sanitizeValue(value, key);
  }
  return sanitized;
}

/**
 * Sanitize a log payload object, ensuring no sensitive data is present.
 * This is the primary entry point for sanitizing log entries before emission.
 *
 * @param payload - The log payload to sanitize
 * @returns A new object safe for logging
 */
export function sanitizeLogPayload(payload: Record<string, unknown>): Record<string, unknown> {
  return sanitizeObject(payload);
}
