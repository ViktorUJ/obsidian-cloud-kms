/**
 * Notice helper functions for displaying user-facing messages.
 * All notices display for at least 5 seconds (NOTICE_DURATION_MS).
 */

import { Notice } from 'obsidian';
import { NOTICE_DURATION_MS } from '../constants';
import { PluginError, ErrorCategory } from '../providers/errors';

/**
 * Category-specific message prefixes for user-friendly error display.
 */
const CATEGORY_PREFIXES: Record<ErrorCategory, string> = {
  credential: 'Authentication failed: ',
  authorization: 'Access denied: ',
  network: 'Network error: ',
  timeout: 'Request timed out',
  integrity: 'Integrity check failed',
  format: 'File format error: ',
  validation: 'Configuration error: ',
  crypto: 'Encryption error: ',
  'size-limit': 'File too large: ',
};

/**
 * Display an error notice with a category-specific prefix.
 * The notice is shown for at least NOTICE_DURATION_MS (5s).
 */
export function showErrorNotice(error: PluginError): void {
  const prefix = CATEGORY_PREFIXES[error.category];
  // Some categories have self-contained prefixes (no trailing colon/space),
  // so only append the error message if the prefix ends with a separator.
  const needsMessage = prefix.endsWith(': ');
  const message = needsMessage ? `${prefix}${error.message}` : prefix;
  new Notice(message, NOTICE_DURATION_MS);
}

/**
 * Display a simple informational notice.
 * The notice is shown for at least NOTICE_DURATION_MS (5s).
 */
export function showNotice(message: string): void {
  new Notice(message, NOTICE_DURATION_MS);
}
