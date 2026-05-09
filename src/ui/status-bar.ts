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

const CHECK_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export function installStatusBar(
  plugin: Plugin,
  getSettings: () => PluginSettings
): () => void {
  const statusBarEl = plugin.addStatusBarItem();
  statusBarEl.addClass('ocke-status-bar');
  statusBarEl.setText('⏳ KMS ...');

  let intervalId: number | null = null;

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
    switch (status) {
      case 'ok':
        statusBarEl.setText('🔓 KMS');
        statusBarEl.setAttribute('title', 'KMS connection OK — encryption/decryption available');
        statusBarEl.style.color = '';
        break;
      case 'error':
        statusBarEl.setText('🔒 KMS ⚠️');
        statusBarEl.setAttribute('title', `KMS unavailable: ${detail}\nSecret blocks will NOT be encrypted on save!`);
        statusBarEl.style.color = 'var(--text-error)';
        break;
      case 'checking':
        statusBarEl.setText('⏳ KMS');
        statusBarEl.setAttribute('title', 'Checking KMS connection...');
        statusBarEl.style.color = 'var(--text-muted)';
        break;
    }
  };

  // Click to re-check
  statusBarEl.addEventListener('click', () => {
    checkStatus();
  });

  // Initial check after layout ready
  plugin.app.workspace.onLayoutReady(() => {
    setTimeout(checkStatus, 2000);
  });

  // Periodic check
  intervalId = window.setInterval(checkStatus, CHECK_INTERVAL_MS);
  plugin.register(() => {
    if (intervalId !== null) window.clearInterval(intervalId);
  });

  return () => {
    if (intervalId !== null) window.clearInterval(intervalId);
    statusBarEl.remove();
  };
}
