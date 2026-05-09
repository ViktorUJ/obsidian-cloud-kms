# Design Document — obsidian-cloud-kms-encryption

## Overview

Obsidian plugin providing transparent envelope encryption of secret blocks in markdown notes and binary files using AWS KMS. The plugin monkey-patches Obsidian's vault adapter to intercept read/write operations, ensuring plaintext never touches disk.

## Architecture

### Core Principle

**Monkey-patch vault adapter** — the plugin intercepts `adapter.read()` and `adapter.write()` at the Obsidian vault level:
- `read()`: decrypts `````ocke-v1` blocks → `%%secret-start%%...%%secret-end%%`
- `write()`: encrypts `%%secret-start%%...%%secret-end%%` → `````ocke-v1` blocks
- `readBinary()`: decrypts OCKE binary files → original bytes
- `getResourcePath()`: returns Blob URL for encrypted binary files

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Obsidian Editor (user sees plaintext)                       │
│  %%secret-start%%                                            │
│  My secret content                                           │
│  %%secret-end%%                                              │
└──────────────────────────┬──────────────────────────────────┘
                           │ adapter.write() intercepted
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Crypto Adapter Patch                                        │
│  1. Find %%secret-start%%...%%secret-end%% blocks            │
│  2. Resolve key alias → ARN                                  │
│  3. CryptoEngine.encrypt(plaintext, ARN)                     │
│  4. Replace with ````ocke-v1\n<base64>\n````                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ original adapter.write()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Disk (only ciphertext)                                      │
│  ````ocke-v1                                                 │
│  T0NLRQABB2F3cy1rbXMA...base64...                            │
│  ````                                                        │
└─────────────────────────────────────────────────────────────┘
```

### Envelope Encryption Flow

```
Encrypt:
  1. GenerateDataKey(CMK) → plaintext DEK + wrapped DEK
  2. AES-256-GCM(DEK, nonce, plaintext) → ciphertext + auth tag
  3. Zero DEK
  4. Store: wrapped DEK + nonce + auth tag + ciphertext

Decrypt:
  1. KMS Decrypt(wrapped DEK, CMK) → plaintext DEK
  2. AES-256-GCM decrypt(DEK, nonce, ciphertext, auth tag) → plaintext
  3. Zero DEK
```

## Components

### Plugin Entry Point (`src/main.ts`)

- Loads settings (multi-key config)
- Creates CryptoEngine with AWS KMS adapter
- Installs crypto adapter patch (monkey-patch)
- Registers commands (wrap/unwrap selection, encrypt/decrypt file)
- Installs file explorer badge (🔒 indicator)
- Cleanup on unload (restore adapter, revoke Blob URLs, zero buffers)

### Crypto Adapter Patch (`src/hooks/crypto-adapter-patch.ts`)

The core of the plugin. Patches:
- `adapter.read()` — decrypt on read
- `adapter.write()` — encrypt on write
- `adapter.readBinary()` — decrypt binary files
- `vault.getResourcePath()` — return Blob URL for encrypted binaries

Features:
- Multi-key support via `%%secret-start:alias%%` syntax
- LRU cache (20 entries) for decrypted binary Blob URLs
- Re-entrancy protection via `processing` Set
- Graceful degradation (returns original content on decrypt failure)

### Key Resolver (`src/utils/key-resolver.ts`)

Resolves key alias to ARN:
1. Explicit alias in marker → lookup in `settings.keys[]`
2. No alias → use `settings.defaultKeyAlias`
3. Fallback → `settings.awsCmkArn` (backward compat)

### AWS KMS Adapter (`src/providers/aws-kms-adapter.ts`)

- Uses `fromIni()` for credential loading (works in Electron)
- Auto-extracts region from ARN
- Client cache per region
- AbortController timeout (10s)
- Error mapping to PluginError categories

### CryptoEngine (`src/core/crypto-engine.ts`)

Orchestrates envelope encryption:
- DEK generation via KMS `GenerateDataKey`
- AES-256-GCM via WebCrypto API
- DEK zeroing after use (even on error)

### Commands

| Command | File | Description |
|---------|------|-------------|
| Wrap selection | `commands/encrypt-selection.ts` | Wraps text in `%%secret-start%%` markers, key picker if multi-key |
| Unwrap selection | `commands/decrypt-selection.ts` | Removes markers |
| Encrypt file | `commands/encrypt-file.ts` | Encrypts binary file in place (OCKE format) |
| Decrypt file | `commands/decrypt-file.ts` | Permanently decrypts binary file |

### File Explorer Badge (`src/ui/file-explorer-badge.ts`)

- Scans vault for OCKE magic bytes on load
- Adds 🔒 CSS pseudo-element to encrypted files
- Updates on encrypt/decrypt commands

## Data Models

### Secret Block Markers

```
%%secret-start%%          — default key
%%secret-start:finance%%  — specific key alias
...content...
%%secret-end%%
```

### On-Disk Format (encrypted markdown blocks)

```
````ocke-v1
<base64-encoded OCKE binary>
````
```

### OCKE Binary Format (for binary files and inside base64)

```
[Magic: "OCKE" 4B][Version: uint16 BE][ProviderIdLen: 1B][ProviderId]
[CmkIdLen: uint16 BE][CmkId][WrappedDekLen: uint16 BE][WrappedDek]
[Nonce: 12B][AuthTag: 16B][CiphertextLen: uint32 BE][Ciphertext]
```

### Settings

```typescript
interface PluginSettings {
  awsCmkArn: string;           // Legacy single key (backward compat)
  keys: KeyConfig[];           // Multi-key config
  defaultKeyAlias: string;     // Default key for encryption
  encryptedNoteSuffix: string; // Legacy (unused in current arch)
  autoDecryptBlocks: boolean;  // Enable/disable auto-decryption
}

interface KeyConfig {
  alias: string;  // Human-readable name (e.g., "finance", "rnd")
  arn: string;    // AWS KMS Key ARN
}
```

## Security Design

### Zero Cleartext on Disk

- `adapter.write()` encrypts BEFORE data reaches filesystem
- Binary files stored as OCKE format (encrypted bytes)
- Pre-commit hook catches edge cases (plugin disabled)

### Memory Handling

- `SecureBuffer`: zero-fill on release
- DEK zeroed immediately after use
- Blob URLs revoked on unload
- LRU eviction for binary file cache (max 20)

### Credential Handling

- No credentials stored by plugin
- `fromIni()` reads `~/.aws/credentials`
- Supports AWS SSO, IAM roles, temporary creds
- Only KMS key ARN stored in settings (not a secret)

### Audit Trail

- Every KMS Decrypt call logged in AWS CloudTrail
- Encryption context: `{vaultName, filePath, formatVersion}`
- Enables: who accessed what, when

## Module Structure

```
src/
├── main.ts                        # Plugin entry, lifecycle
├── types.ts                       # Interfaces
├── constants.ts                   # Magic bytes, limits
├── core/
│   ├── crypto-engine.ts           # Envelope encryption orchestration
│   ├── secure-buffer.ts           # Zero-fill buffer
│   ├── buffer-registry.ts         # Buffer lifecycle tracking
│   └── webcrypto.ts               # AES-256-GCM via WebCrypto
├── format/
│   ├── serializer.ts              # OCKE binary → bytes
│   ├── parser.ts                  # bytes → OCKE record
│   ├── inline-codec.ts            # base64 encode/decode
│   └── validators.ts              # Field constraints
├── hooks/
│   └── crypto-adapter-patch.ts    # Monkey-patch adapter (core)
├── providers/
│   ├── aws-kms-adapter.ts         # AWS KMS implementation
│   ├── dispatcher.ts              # Provider registry
│   └── errors.ts                  # PluginError
├── commands/
│   ├── encrypt-selection.ts       # Wrap in secret block
│   ├── decrypt-selection.ts       # Unwrap secret block
│   ├── encrypt-file.ts            # Encrypt binary file
│   └── decrypt-file.ts            # Decrypt binary file
├── ui/
│   ├── settings-tab.ts            # Plugin settings
│   ├── file-explorer-badge.ts     # 🔒 indicator
│   ├── encrypted-view.ts          # Fallback view
│   └── notices.ts                 # Notice helpers
├── utils/
│   ├── key-resolver.ts            # Alias → ARN resolution
│   ├── arn-validator.ts           # ARN format validation
│   ├── atomic-write.ts            # Safe file write
│   └── frontmatter.ts            # YAML frontmatter split
└── logging/
    ├── structured-logger.ts       # JSON logging
    └── sanitizer.ts               # Strip sensitive data

tools/
├── ocke-decrypt.sh                # Bash CLI decrypt (AWS CLI + Python)
├── ocke-decrypt.mjs               # Node.js CLI decrypt
└── pre-commit-hook.sh             # Git plaintext leak protection
```

## Build & CI

- **esbuild** with `platform: 'node'` (Electron has Node.js APIs)
- **Node.js builtins** available at runtime (not bundled)
- **CI**: typecheck → lint → test (357) → build → SBOM → release → cosign → SLSA attestation
- **CodeQL**: weekly SAST scanning
- **Dependabot**: weekly dependency updates
- **Auto-release**: patch version bump on every push to main
