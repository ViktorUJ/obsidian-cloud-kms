/**
 * Shared TypeScript interfaces and types for the obsidian-cloud-kms-encryption plugin.
 */

/**
 * Encryption context passed to KMS for audit trail binding.
 * Must be identical for wrap and unwrap of the same DEK.
 */
export interface EncryptionContext {
  vaultName: string;
  filePath: string;
  formatVersion: number;
}

/**
 * Result of a DEK generation + wrap operation.
 */
export interface GenerateDataKeyResult {
  /** Plaintext DEK bytes (256-bit / 32 bytes). Caller MUST zero after use. */
  plaintextDek: Uint8Array;
  /** DEK encrypted by the CMK. Safe to persist. */
  wrappedDek: Uint8Array;
}

/**
 * Provider Adapter interface — the single extension point for KMS providers.
 * Each adapter implements this interface for one cloud provider.
 */
export interface ProviderAdapter {
  /** Unique provider identifier: 1–32 lowercase ASCII alphanumeric + hyphens */
  readonly providerId: string;

  /**
   * Generate a fresh 256-bit DEK and return both plaintext and wrapped forms.
   * @param cmkId - Provider-specific CMK identifier (ARN, URI, resource name)
   * @param context - Encryption context for audit binding
   */
  generateDataKey(
    cmkId: string,
    context: EncryptionContext
  ): Promise<GenerateDataKeyResult>;

  /**
   * Wrap (encrypt) an existing DEK with the specified CMK.
   * Used during key rotation to re-wrap under a new CMK.
   * @param dek - Plaintext DEK bytes (32 bytes)
   * @param cmkId - Target CMK identifier
   * @param context - Encryption context for audit binding
   */
  wrapDek(
    dek: Uint8Array,
    cmkId: string,
    context: EncryptionContext
  ): Promise<Uint8Array>;

  /**
   * Unwrap (decrypt) a wrapped DEK using the specified CMK.
   * @param wrappedDek - Encrypted DEK bytes
   * @param cmkId - CMK identifier used for the original wrap
   * @param context - Encryption context (must match wrap-time context)
   */
  unwrapDek(
    wrappedDek: Uint8Array,
    cmkId: string,
    context: EncryptionContext
  ): Promise<Uint8Array>;

  /**
   * Validate that credentials are available and the CMK is accessible.
   * Used for settings validation and health checks.
   * @param cmkId - CMK identifier to validate
   */
  validateAccess(cmkId: string): Promise<void>;
}

/**
 * CryptoEngine interface — orchestrates envelope encryption.
 */
export interface CryptoEngine {
  /**
   * Encrypt plaintext using envelope encryption.
   * Generates DEK + nonce locally, encrypts with AES-256-GCM,
   * wraps DEK via provider, returns serializable record.
   */
  encrypt(
    plaintext: Uint8Array,
    cmkId: string,
    providerId: string,
    context: EncryptionContext
  ): Promise<EncryptedFileRecord>;

  /**
   * Decrypt an EncryptedFileRecord back to plaintext.
   * Unwraps DEK via provider, decrypts with AES-256-GCM,
   * verifies authentication tag.
   */
  decrypt(
    record: EncryptedFileRecord,
    context: EncryptionContext
  ): Promise<Uint8Array>;
}

/**
 * Provider Dispatcher — registry and routing for provider adapters.
 */
export interface ProviderDispatcher {
  /**
   * Register a provider adapter. Rejects duplicates.
   * @throws if providerId already registered or interface incomplete
   */
  register(adapter: ProviderAdapter): void;

  /**
   * Get adapter by provider identifier.
   * @throws ProviderNotFoundError if not registered
   */
  getAdapter(providerId: string): ProviderAdapter;

  /** List all registered provider identifiers */
  listProviders(): string[];
}

/**
 * Wrapper around Uint8Array that guarantees zero-fill on release.
 * Prevents plaintext from lingering in GC-managed memory.
 */
export interface SecureBuffer {
  readonly bytes: Uint8Array;
  readonly length: number;
  /** Zero-fill the buffer and mark as released. Further access throws. */
  release(): void;
  /** Whether the buffer has been released */
  readonly isReleased: boolean;
}

/**
 * On-disk encrypted file record structure.
 */
export interface EncryptedFileRecord {
  magic: Uint8Array;          // 4 bytes: 0x4F 0x43 0x4B 0x45 ("OCKE")
  version: number;            // uint16, current = 1
  providerId: string;         // 1–32 chars ASCII
  cmkId: string;              // variable length, provider-specific
  wrappedDek: Uint8Array;     // variable length (provider-dependent)
  nonce: Uint8Array;          // 12 bytes (96-bit)
  authTag: Uint8Array;        // 16 bytes (128-bit)
  ciphertext: Uint8Array;     // variable length
}

/**
 * Plugin settings data model.
 */
export interface PluginSettings {
  // Primary key (backward compat)
  awsCmkArn: string;

  // Multi-key support
  keys: KeyConfig[];
  defaultKeyAlias: string;

  // Behavior
  encryptedNoteSuffix: string;
  autoDecryptBlocks: boolean;

  // Phase 3 (future)
  providers: ProviderConfig[];
  vaultPolicies: EncryptedVaultPolicy[];
}

/**
 * Named KMS key configuration.
 */
export interface KeyConfig {
  alias: string;
  arn: string;
}

/**
 * Configuration for a single KMS provider.
 */
export interface ProviderConfig {
  providerId: string;
  enabled: boolean;
  cmkId: string;
}

/**
 * Per-folder encrypted vault policy binding.
 */
export interface EncryptedVaultPolicy {
  folderPath: string;
  providerId: string;
  cmkId: string;
}
