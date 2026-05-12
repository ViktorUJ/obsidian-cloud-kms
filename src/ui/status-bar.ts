/**
 * Status bar indicator showing KMS connection status.
 *
 * Displays in Obsidian's bottom status bar:
 * - 🔓 KMS OK     — credentials valid, key accessible
 * - 🔒 KMS ⚠️     — cannot reach KMS (no credentials, network, or key access)
 * - ⏳ KMS ...    — checking connection
 *
 * Checks on:
 * - Plugin load
 * - Every 5 minutes (background)
 * - Manual click on status bar item
 */

import { Plugin } from 'obsidian';
import type { PluginSettings } from '../types';
import { AwsKmsAdapter } from '../providers/aws-kms-adapter';
import { resolveKeyArn } from '../utils/key-resolver';

export function installStatusBar(
  plugin: Plugin,
  getSettings: () => PluginSettings
): () => void {
  const statusBarEl = plugin.addStatusBarItem();
  statusBarEl.addClass('ocke-status-bar');
  statusBarEl.setText('⏳ KMS ...');

  const checkStatus = async () => {
    const settings = getSettings();
    const arn = resolveKeyArn(undefined, settings);

    if (!arn) {
      setStatus('error', 'No key configured');
      return;
    }

    setStatus('checking', '');

    try {
      const adapter = new AwsKmsAdapter(undefined, 5000); // 5s timeout for health check
      await adapter.validateAccess(arn);
      setStatus('ok', '');
    } catch {
      setStatus('error', 'Cannot reach KMS');
    }
  };

  const setStatus = (status: 'ok' | 'error' | 'checking', detail: string) => {
    statusBarEl.removeClass('ocke-status-bar--ok', 'ocke-status-bar--error', 'ocke-status-bar--checking');
    switch (status) {
      case 'ok':
        statusBarEl.setText('🔓 KMS');
        statusBarEl.setAttribute('title', 'KMS connection OK — encryption/decryption available');
        statusBarEl.addClass('ocke-status-bar--ok');
        break;
      case 'error':
        statusBarEl.setText('🔒 KMS ⚠️');
        statusBarEl.setAttribute('title', `KMS unavailable: ${detail}\nSecret blocks will NOT be encrypted on save!`);
        statusBarEl.addClass('ocke-status-bar--error');
        break;
      case 'checking':
        statusBarEl.setText('⏳ KMS');
        statusBarEl.setAttribute('title', 'Checking KMS connection...');
        statusBarEl.addClass('ocke-status-bar--checking');
        break;
    }
  };

  // Check on click only (no periodic background checks)
  statusBarEl.addEventListener('click', () => {
    void checkStatus();
  });

  // Initial check after layout ready
  plugin.app.workspace.onLayoutReady(() => {
    window.setTimeout(checkStatus, 2000);
  });

  return () => {
    statusBarEl.remove();
  };
}
