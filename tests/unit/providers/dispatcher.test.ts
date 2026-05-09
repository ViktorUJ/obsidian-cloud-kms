import { describe, it, expect, beforeEach } from 'vitest';
import { ProviderDispatcherImpl } from '../../../src/providers/dispatcher';
import { ProviderAdapter, EncryptionContext, GenerateDataKeyResult } from '../../../src/types';
import { PluginError } from '../../../src/providers/errors';

/**
 * Creates a mock ProviderAdapter with all required methods.
 */
function createMockAdapter(providerId: string): ProviderAdapter {
  return {
    providerId,
    generateDataKey: async (_cmkId: string, _context: EncryptionContext): Promise<GenerateDataKeyResult> => ({
      plaintextDek: new Uint8Array(32),
      wrappedDek: new Uint8Array(64),
    }),
    wrapDek: async (_dek: Uint8Array, _cmkId: string, _context: EncryptionContext): Promise<Uint8Array> =>
      new Uint8Array(64),
    unwrapDek: async (_wrappedDek: Uint8Array, _cmkId: string, _context: EncryptionContext): Promise<Uint8Array> =>
      new Uint8Array(32),
    validateAccess: async (_cmkId: string): Promise<void> => {},
  };
}

describe('ProviderDispatcherImpl', () => {
  let dispatcher: ProviderDispatcherImpl;

  beforeEach(() => {
    dispatcher = new ProviderDispatcherImpl();
  });

  describe('register()', () => {
    it('should register a valid adapter', () => {
      const adapter = createMockAdapter('aws-kms');
      dispatcher.register(adapter);
      expect(dispatcher.listProviders()).toContain('aws-kms');
    });

    it('should register multiple adapters with different providerIds', () => {
      dispatcher.register(createMockAdapter('aws-kms'));
      dispatcher.register(createMockAdapter('azure-key-vault'));
      dispatcher.register(createMockAdapter('gcp-kms'));
      expect(dispatcher.listProviders()).toEqual(['aws-kms', 'azure-key-vault', 'gcp-kms']);
    });

    it('should reject duplicate providerId with validation error', () => {
      dispatcher.register(createMockAdapter('aws-kms'));
      expect(() => dispatcher.register(createMockAdapter('aws-kms'))).toThrow(PluginError);
      try {
        dispatcher.register(createMockAdapter('aws-kms'));
      } catch (e) {
        expect(e).toBeInstanceOf(PluginError);
        expect((e as PluginError).category).toBe('validation');
        expect((e as PluginError).message).toContain('already registered');
      }
    });

    it('should reject adapter with empty providerId', () => {
      const adapter = createMockAdapter('');
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
      try {
        dispatcher.register(adapter);
      } catch (e) {
        expect((e as PluginError).category).toBe('validation');
        expect((e as PluginError).message).toContain('Invalid provider identifier');
      }
    });

    it('should reject adapter with providerId containing uppercase', () => {
      const adapter = createMockAdapter('AWS-KMS');
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
    });

    it('should reject adapter with providerId containing special characters', () => {
      const adapter = createMockAdapter('aws_kms');
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
    });

    it('should reject adapter with providerId longer than 32 characters', () => {
      const adapter = createMockAdapter('a'.repeat(33));
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
    });

    it('should accept adapter with single character providerId', () => {
      const adapter = createMockAdapter('a');
      dispatcher.register(adapter);
      expect(dispatcher.listProviders()).toContain('a');
    });

    it('should accept adapter with 32 character providerId', () => {
      const adapter = createMockAdapter('a'.repeat(32));
      dispatcher.register(adapter);
      expect(dispatcher.listProviders()).toContain('a'.repeat(32));
    });

    it('should reject adapter with providerId starting with hyphen', () => {
      const adapter = createMockAdapter('-aws-kms');
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
    });

    it('should reject adapter with providerId ending with hyphen', () => {
      const adapter = createMockAdapter('aws-kms-');
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
    });

    it('should reject adapter missing generateDataKey method', () => {
      const adapter = createMockAdapter('test') as Record<string, unknown>;
      delete adapter.generateDataKey;
      expect(() => dispatcher.register(adapter as unknown as ProviderAdapter)).toThrow(PluginError);
      try {
        dispatcher.register(adapter as unknown as ProviderAdapter);
      } catch (e) {
        expect((e as PluginError).category).toBe('validation');
        expect((e as PluginError).message).toContain('generateDataKey');
      }
    });

    it('should reject adapter missing multiple methods', () => {
      const adapter = {
        providerId: 'test',
      } as unknown as ProviderAdapter;
      try {
        dispatcher.register(adapter);
      } catch (e) {
        expect((e as PluginError).category).toBe('validation');
        expect((e as PluginError).message).toContain('generateDataKey');
        expect((e as PluginError).message).toContain('wrapDek');
        expect((e as PluginError).message).toContain('unwrapDek');
        expect((e as PluginError).message).toContain('validateAccess');
      }
    });

    it('should reject adapter where a required method is not a function', () => {
      const adapter = {
        providerId: 'test',
        generateDataKey: 'not a function',
        wrapDek: async () => new Uint8Array(64),
        unwrapDek: async () => new Uint8Array(32),
        validateAccess: async () => {},
      } as unknown as ProviderAdapter;
      expect(() => dispatcher.register(adapter)).toThrow(PluginError);
      try {
        dispatcher.register(adapter);
      } catch (e) {
        expect((e as PluginError).message).toContain('generateDataKey');
      }
    });
  });

  describe('getAdapter()', () => {
    it('should return the registered adapter by providerId', () => {
      const adapter = createMockAdapter('aws-kms');
      dispatcher.register(adapter);
      expect(dispatcher.getAdapter('aws-kms')).toBe(adapter);
    });

    it('should throw PluginError with format category for unregistered providerId', () => {
      expect(() => dispatcher.getAdapter('nonexistent')).toThrow(PluginError);
      try {
        dispatcher.getAdapter('nonexistent');
      } catch (e) {
        expect(e).toBeInstanceOf(PluginError);
        expect((e as PluginError).category).toBe('format');
        expect((e as PluginError).message).toContain('not registered');
      }
    });

    it('should return correct adapter when multiple are registered', () => {
      const aws = createMockAdapter('aws-kms');
      const azure = createMockAdapter('azure-key-vault');
      dispatcher.register(aws);
      dispatcher.register(azure);
      expect(dispatcher.getAdapter('aws-kms')).toBe(aws);
      expect(dispatcher.getAdapter('azure-key-vault')).toBe(azure);
    });
  });

  describe('listProviders()', () => {
    it('should return empty array when no providers registered', () => {
      expect(dispatcher.listProviders()).toEqual([]);
    });

    it('should return all registered provider IDs', () => {
      dispatcher.register(createMockAdapter('aws-kms'));
      dispatcher.register(createMockAdapter('gcp-kms'));
      const providers = dispatcher.listProviders();
      expect(providers).toHaveLength(2);
      expect(providers).toContain('aws-kms');
      expect(providers).toContain('gcp-kms');
    });

    it('should return a new array each time (not a reference to internal state)', () => {
      dispatcher.register(createMockAdapter('aws-kms'));
      const list1 = dispatcher.listProviders();
      const list2 = dispatcher.listProviders();
      expect(list1).toEqual(list2);
      expect(list1).not.toBe(list2);
    });
  });
});
