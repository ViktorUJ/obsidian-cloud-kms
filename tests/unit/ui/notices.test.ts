/**
 * Unit tests for notice helper functions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Notice } from 'obsidian';
import { showErrorNotice, showNotice } from '../../../src/ui/notices';
import { PluginError, ErrorCategory } from '../../../src/providers/errors';
import { NOTICE_DURATION_MS } from '../../../src/constants';

vi.mock('obsidian');

describe('showErrorNotice', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('displays credential error with prefix and message', () => {
    const error = new PluginError('invalid token', 'credential');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Authentication failed: invalid token', NOTICE_DURATION_MS);
  });

  it('displays authorization error with prefix and message', () => {
    const error = new PluginError('key policy denies access', 'authorization');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Access denied: key policy denies access', NOTICE_DURATION_MS);
  });

  it('displays network error with prefix and message', () => {
    const error = new PluginError('connection refused', 'network');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Network error: connection refused', NOTICE_DURATION_MS);
  });

  it('displays timeout error as self-contained message', () => {
    const error = new PluginError('exceeded 10s', 'timeout');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Request timed out', NOTICE_DURATION_MS);
  });

  it('displays integrity error as self-contained message', () => {
    const error = new PluginError('auth tag mismatch', 'integrity');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Integrity check failed', NOTICE_DURATION_MS);
  });

  it('displays format error with prefix and message', () => {
    const error = new PluginError('unsupported version 99', 'format');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('File format error: unsupported version 99', NOTICE_DURATION_MS);
  });

  it('displays validation error with prefix and message', () => {
    const error = new PluginError('invalid ARN format', 'validation');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Configuration error: invalid ARN format', NOTICE_DURATION_MS);
  });

  it('displays crypto error with prefix and message', () => {
    const error = new PluginError('WebCrypto unavailable', 'crypto');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('Encryption error: WebCrypto unavailable', NOTICE_DURATION_MS);
  });

  it('displays size-limit error with prefix and message', () => {
    const error = new PluginError('exceeds 50 MB limit', 'size-limit');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith('File too large: exceeds 50 MB limit', NOTICE_DURATION_MS);
  });

  it('uses NOTICE_DURATION_MS (5000ms) for all error notices', () => {
    const error = new PluginError('test', 'network');
    showErrorNotice(error);
    expect(Notice).toHaveBeenCalledWith(expect.any(String), 5000);
  });
});

describe('showNotice', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('displays a simple message with NOTICE_DURATION_MS', () => {
    showNotice('Encryption complete');
    expect(Notice).toHaveBeenCalledWith('Encryption complete', NOTICE_DURATION_MS);
  });

  it('passes the exact message string provided', () => {
    showNotice('File decrypted successfully');
    expect(Notice).toHaveBeenCalledWith('File decrypted successfully', NOTICE_DURATION_MS);
  });
});
