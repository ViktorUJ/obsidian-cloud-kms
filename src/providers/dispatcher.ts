/**
 * Provider Dispatcher — registry and routing for provider adapters.
 *
 * Maintains a map of providerId → ProviderAdapter and validates
 * adapters on registration (duplicate check, interface completeness).
 */

import { ProviderAdapter, ProviderDispatcher } from '../types';
import { PluginError } from './errors';

/**
 * Regex for valid provider identifiers: 1–32 lowercase ASCII alphanumeric + hyphens.
 * Must not start or end with a hyphen.
 */
const PROVIDER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$|^[a-z0-9]$/;

/**
 * Required methods that every ProviderAdapter must implement.
 */
const REQUIRED_METHODS: ReadonlyArray<keyof ProviderAdapter> = [
  'generateDataKey',
  'wrapDek',
  'unwrapDek',
  'validateAccess',
];

/**
 * Implementation of the ProviderDispatcher interface.
 * Manages a registry of provider adapters keyed by providerId.
 */
export class ProviderDispatcherImpl implements ProviderDispatcher {
  private readonly registry: Map<string, ProviderAdapter> = new Map();

  /**
   * Register a provider adapter.
   * Validates that the adapter has a valid providerId and implements all required methods.
   * Rejects duplicate providerIds and incomplete interface implementations.
   *
   * @throws PluginError with category 'validation' if providerId is already registered
   * @throws PluginError with category 'validation' if providerId format is invalid
   * @throws PluginError with category 'validation' if interface is incomplete
   */
  register(adapter: ProviderAdapter): void {
    // Validate providerId format
    if (!adapter.providerId || !PROVIDER_ID_PATTERN.test(adapter.providerId)) {
      throw new PluginError(
        `Invalid provider identifier "${adapter.providerId}": must be 1–32 lowercase ASCII alphanumeric characters and hyphens`,
        'validation'
      );
    }

    // Check for duplicate registration
    if (this.registry.has(adapter.providerId)) {
      throw new PluginError(
        `Provider "${adapter.providerId}" is already registered`,
        'validation',
        adapter.providerId
      );
    }

    // Validate interface completeness
    const missingMethods: string[] = [];
    for (const method of REQUIRED_METHODS) {
      if (typeof (adapter as unknown as Record<string, unknown>)[method] !== 'function') {
        missingMethods.push(method);
      }
    }

    if (missingMethods.length > 0) {
      throw new PluginError(
        `Provider "${adapter.providerId}" is missing required methods: ${missingMethods.join(', ')}`,
        'validation',
        adapter.providerId
      );
    }

    this.registry.set(adapter.providerId, adapter);
  }

  /**
   * Get adapter by provider identifier.
   *
   * @throws PluginError with category 'format' if provider is not registered
   */
  getAdapter(providerId: string): ProviderAdapter {
    const adapter = this.registry.get(providerId);
    if (!adapter) {
      throw new PluginError(
        `Provider "${providerId}" is not registered`,
        'format',
        providerId
      );
    }
    return adapter;
  }

  /**
   * List all registered provider identifiers.
   */
  listProviders(): string[] {
    return Array.from(this.registry.keys());
  }
}
