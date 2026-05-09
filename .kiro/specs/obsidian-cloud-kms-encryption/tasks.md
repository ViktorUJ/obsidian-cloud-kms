# Implementation Plan: obsidian-cloud-kms-encryption

## Overview

This plan implements the Obsidian Cloud KMS Encryption plugin in three phases (PoC → MVP → Advanced), following the modular architecture from the design document. Tasks are ordered bottom-up: core crypto primitives first, then format layer, providers, hooks, commands, policies, and finally UI. Each task is scoped to 1–2 hours of focused coding work.

## Tasks

- [x] 1. Project scaffolding and core infrastructure
  - [x] 1.1 Initialize project structure and build tooling
    - Create `package.json` with exact-pinned dependencies (`obsidian`, `@aws-sdk/client-kms`, `esbuild`, `vitest`, `fast-check`, TypeScript)
    - Create `tsconfig.json` targeting ES2021 with strict mode
    - Create `esbuild.config.mjs` for Obsidian plugin bundling (single `main.js` output)
    - Create `vitest.config.ts` with TypeScript support
    - Create `manifest.json` and `versions.json` for Obsidian plugin metadata
    - Create directory structure: `src/{core,format,providers,hooks,commands,policies,ui,logging,utils}` and `tests/{unit,property,integration}`
    - _Requirements: 17.1, 17.2, 17.4_

  - [x] 1.2 Define shared types, constants, and error classes
    - Create `src/types.ts` with all interfaces: `EncryptionContext`, `GenerateDataKeyResult`, `ProviderAdapter`, `CryptoEngine`, `ProviderDispatcher`, `SecureBuffer`, `EncryptedFileRecord`, `PluginSettings`
    - Create `src/constants.ts` with magic bytes (`0x4F434B45`), version (1), field limits, timeout defaults
    - Create `src/providers/errors.ts` with `PluginError` class and `ErrorCategory` type
    - _Requirements: 9.2, 8.1, 16.1_

- [x] 2. Core cryptographic primitives (Phase 1 foundation)
  - [x] 2.1 Implement SecureBuffer and BufferRegistry
    - Create `src/core/secure-buffer.ts`: `SecureBuffer` class wrapping `Uint8Array` with zero-fill on `release()`
    - Create `src/core/buffer-registry.ts`: tracks active buffers, force-releases all on plugin unload
    - Ensure no string conversion of sensitive data
    - _Requirements: 12.1, 12.3, 12.4_

  - [ ]* 2.2 Write unit tests for SecureBuffer
    - Test zero-fill on release, double-release throws, access after release throws
    - Test BufferRegistry cleanup on force-release-all
    - _Requirements: 12.1, 12.3_

  - [x] 2.3 Implement WebCrypto wrapper
    - Create `src/core/webcrypto.ts`: AES-256-GCM encrypt/decrypt using `crypto.subtle`
    - Functions: `generateDek()` → 32 random bytes, `generateNonce()` → 12 random bytes, `aesGcmEncrypt(key, nonce, plaintext)` → `{ciphertext, authTag}`, `aesGcmDecrypt(key, nonce, ciphertext, authTag)` → plaintext
    - All operations on `Uint8Array`, no string intermediates
    - _Requirements: 13.1, 17.2, 1.2, 1.4_

  - [ ]* 2.4 Write unit tests for WebCrypto wrapper
    - Test encrypt/decrypt with known test vectors
    - Test auth tag verification failure on tampered ciphertext
    - Test nonce uniqueness across calls
    - _Requirements: 13.1, 19.3_

- [x] 3. On-Disk Format layer
  - [x] 3.1 Implement serializer
    - Create `src/format/serializer.ts`: encode `EncryptedFileRecord` → `Uint8Array` per On-Disk Format spec (big-endian, length-prefixed fields)
    - Create `src/format/validators.ts`: field constraint validation (magic, version, providerId length/charset, cmkId length, wrappedDek length, ciphertext length)
    - Abort with descriptive error on any constraint violation
    - _Requirements: 18.1, 18.6, 8.1_

  - [x] 3.2 Implement parser
    - Create `src/format/parser.ts`: decode `Uint8Array` → `EncryptedFileRecord`
    - Validate magic bytes, version, all field lengths, reject trailing bytes
    - Return descriptive parse error on first invalid field
    - _Requirements: 18.2, 18.3, 8.2, 8.3, 8.4, 8.5_

  - [ ]* 3.3 Write property test: Serializer Round-Trip (Property 1)
    - **Property 1: Serializer Round-Trip (serialize → parse)**
    - Create `tests/property/format/serializer.property.test.ts`
    - Generator: random valid `EncryptedFileRecord` with fields within all declared constraints
    - Assert: `parse(serialize(record))` equals original record field-by-field
    - **Validates: Requirements 18.4**

  - [ ]* 3.4 Write property test: Parser Round-Trip (Property 2)
    - **Property 2: Parser Round-Trip (parse → serialize)**
    - Create `tests/property/format/parser.property.test.ts`
    - Generator: random valid on-disk format byte sequences
    - Assert: `serialize(parse(bytes))` equals original bytes
    - **Validates: Requirements 18.5**

  - [x] 3.5 Implement inline codec for Phase 1
    - Create `src/format/inline-codec.ts`: encode binary On-Disk Format to base64 inside `` ```ocke-v1 `` fenced block, decode back
    - Detect `ocke-v1` fence markers in Markdown text, extract and base64-decode content
    - _Requirements: 1.5, 2.2_

  - [ ]* 3.6 Write unit tests for inline codec
    - Test round-trip encode/decode
    - Test detection of fence markers in surrounding Markdown
    - Test rejection of malformed base64 content
    - _Requirements: 1.5, 2.2, 2.7_

- [x] 4. Checkpoint — Core and format layers
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Provider Dispatcher and AWS KMS Adapter (Phase 1)
  - [x] 5.1 Implement Provider Dispatcher
    - Create `src/providers/dispatcher.ts`: registry map by providerId, `register()` with duplicate/interface validation, `getAdapter()`, `listProviders()`
    - Reject duplicate providerId, reject incomplete interface implementations
    - _Requirements: 9.3, 9.4, 9.5, 9.6, 16.2, 16.4, 16.5_

  - [ ]* 5.2 Write property test: Confluence of Provider Adapter Dispatch (Property 9)
    - **Property 9: Confluence of Provider Adapter Dispatch**
    - Create `tests/property/providers/dispatcher.property.test.ts`
    - Generator: random sets of mock adapters (up to 64), random permutations of registration order
    - Assert: same success/failure classification and identical dispatch results regardless of registration order
    - **Validates: Requirements 22.1, 22.2**

  - [x] 5.3 Implement AWS KMS Adapter
    - Create `src/providers/aws-kms-adapter.ts`: implements `ProviderAdapter` using `@aws-sdk/client-kms`
    - `generateDataKey`: call KMS `GenerateDataKeyCommand` with AES_256
    - `wrapDek`: call KMS `EncryptCommand`
    - `unwrapDek`: call KMS `DecryptCommand`
    - `validateAccess`: call KMS `DescribeKeyCommand`
    - Include `AbortController` timeout (10s default), encryption context passing
    - _Requirements: 1.3, 3.1, 3.2, 15.1, 15.2_

  - [ ]* 5.4 Write unit tests for AWS KMS Adapter
    - Mock `@aws-sdk/client-kms` client
    - Test successful generateDataKey, wrapDek, unwrapDek flows
    - Test timeout handling (AbortController), credential errors, authorization errors
    - Test encryption context is passed correctly
    - _Requirements: 3.1, 3.3, 3.4, 14.4_

- [x] 6. CryptoEngine — Envelope encryption orchestration
  - [x] 6.1 Implement CryptoEngine
    - Create `src/core/crypto-engine.ts`: orchestrates DEK generation, AES-256-GCM encrypt/decrypt, provider dispatch for wrap/unwrap
    - `encrypt()`: generate DEK → generate nonce → AES-GCM encrypt → wrap DEK via dispatcher → zero DEK → return `EncryptedFileRecord`
    - `decrypt()`: unwrap DEK via dispatcher → AES-GCM decrypt → verify auth tag → zero DEK → return plaintext
    - Always zero DEK on success or failure
    - _Requirements: 1.2, 1.4, 2.2, 2.3, 12.1, 13.1_

  - [ ]* 6.2 Write property test: Encrypt/Decrypt Round-Trip (Property 3)
    - **Property 3: Encrypt/Decrypt Round-Trip**
    - Create `tests/property/core/crypto-engine.property.test.ts`
    - Generator: random `Uint8Array` (0–1 MiB), mock KMS adapter
    - Assert: `decrypt(encrypt(P)) === P` byte-for-byte
    - **Validates: Requirements 19.1, 5.7, 6.2**

  - [ ]* 6.3 Write property test: Encryption Freshness (Property 4)
    - **Property 4: Encryption Freshness**
    - Add to `tests/property/core/crypto-engine.property.test.ts`
    - Generator: random plaintext, encrypt twice with same CMK
    - Assert: DEK bytes differ AND nonce bytes differ between two encryptions
    - **Validates: Requirements 19.2, 1.2, 1.4**

  - [ ]* 6.4 Write property test: Tamper Detection (Property 5)
    - **Property 5: Tamper Detection**
    - Add to `tests/property/core/crypto-engine.property.test.ts`
    - Generator: valid encrypted file, random byte position flip in ciphertext/nonce/wrappedDek/authTag
    - Assert: decrypt aborts with integrity error, no plaintext returned
    - **Validates: Requirements 19.3**

  - [ ]* 6.5 Write property test: No Plaintext Leakage on Disk (Property 7)
    - **Property 7: No Plaintext Leakage on Disk**
    - Add to `tests/property/core/crypto-engine.property.test.ts`
    - Generator: random plaintext ≥32 bytes, encrypt via save path
    - Assert: output bytes do not contain plaintext as contiguous substring, no 32-byte substring with Shannon entropy >3 bits/byte
    - **Validates: Requirements 21.1, 21.2, 12.1, 12.2**

  - [ ]* 6.6 Write property test: No DEK Leakage on Disk (Property 8)
    - **Property 8: No DEK Leakage on Disk**
    - Add to `tests/property/core/crypto-engine.property.test.ts`
    - Generator: run full encrypt flow, capture DEK before zeroing
    - Assert: no output artifact contains DEK or any 16-byte substring of DEK
    - **Validates: Requirements 21.4**

- [x] 7. Checkpoint — Crypto engine and providers
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Utility modules
  - [x] 8.1 Implement ARN validator
    - Create `src/utils/arn-validator.ts`: validate AWS KMS ARN format `arn:aws:kms:{region}:{12-digit-account}:key/{key-id}`
    - Return validation result with error message for invalid formats
    - Handle empty/whitespace-only input
    - _Requirements: 4.2, 4.3, 4.4_

  - [ ]* 8.2 Write property test: ARN Validation Consistency (Property 13)
    - **Property 13: ARN Validation Consistency**
    - Create `tests/property/utils/arn-validator.property.test.ts`
    - Generator: random strings (valid ARNs, invalid strings, whitespace, edge cases)
    - Assert: empty/whitespace → disabled; non-matching pattern → validation error; matching pattern → no error
    - **Validates: Requirements 4.2, 4.3, 4.4**

  - [x] 8.3 Implement frontmatter splitter
    - Create `src/utils/frontmatter.ts`: detect YAML frontmatter block (`---` delimiters), split note into frontmatter + body
    - Handle notes with no frontmatter (entire content is body)
    - _Requirements: 5.3, 5.4_

  - [x] 8.4 Implement atomic file write utility
    - Create `src/utils/atomic-write.ts`: write to temp file → rename to target; rollback on failure
    - Use Obsidian Vault adapter API (`writeBinary`, `rename`, `remove`)
    - _Requirements: 5.5, 7.2, 7.3, 11.2_

  - [x] 8.5 Implement structured logger and sanitizer
    - Create `src/logging/structured-logger.ts`: emit structured JSON log entries (info/error) with timestamp, provider, cmkId, filePath, payload size
    - Create `src/logging/sanitizer.ts`: strip plaintext, DEK, credentials from log payloads
    - _Requirements: 15.3, 15.4, 15.5, 15.6_

- [x] 9. Phase 1 Commands
  - [x] 9.1 Implement "Encrypt selection with AWS KMS" command
    - Create `src/commands/encrypt-selection.ts`
    - Register command in Obsidian command palette
    - Validate: active editor, non-empty selection (1–1,048,576 chars), valid CMK ARN configured
    - Flow: encode selection to UTF-8 → CryptoEngine.encrypt → inline-codec encode → replace selection
    - Display Obsidian notice on error (≥5s), abort without modifying editor on failure
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

  - [x] 9.2 Implement "Decrypt selection with AWS KMS" command
    - Create `src/commands/decrypt-selection.ts`
    - Register command in Obsidian command palette
    - Validate: non-empty selection containing parseable `ocke-v1` block
    - Flow: inline-codec decode → parser → CryptoEngine.decrypt → replace selection with plaintext (in editor buffer only)
    - Display Obsidian notice on integrity failure, KMS error, timeout (≥5s)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

  - [ ]* 9.3 Write unit tests for encrypt/decrypt selection commands
    - Mock Obsidian editor API, mock CryptoEngine
    - Test: valid selection → encrypted block replaces selection
    - Test: empty selection → notice, no change
    - Test: KMS error → notice, selection unchanged
    - Test: invalid ARN → command disabled
    - _Requirements: 1.6, 1.7, 1.8, 2.5, 2.6, 2.7_

- [x] 10. Plugin entry point and settings (Phase 1)
  - [x] 10.1 Implement settings tab with ARN field
    - Create `src/ui/settings-tab.ts`: Obsidian `PluginSettingTab` with "AWS KMS Key ARN" text input
    - Inline ARN validation with error display
    - Persist settings via Obsidian `loadData`/`saveData`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 10.2 Implement plugin main entry point
    - Create `src/main.ts`: `Plugin` subclass with `onload()`/`onunload()`
    - Register commands, settings tab, provider dispatcher with AWS adapter
    - On unload: force-release all SecureBuffers via BufferRegistry
    - _Requirements: 1.1, 2.1, 12.4_

  - [ ]* 10.3 Write unit tests for settings and plugin lifecycle
    - Test settings persistence round-trip
    - Test ARN validation in settings UI
    - Test plugin unload cleans up buffers
    - _Requirements: 4.5, 12.4_

- [x] 11. Checkpoint — Phase 1 (PoC) complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Phase 2 — Transparent file encryption hooks
  - [x] 12.1 Implement suffix matcher
    - Create `src/policies/suffix-matcher.ts`: case-sensitive suffix match on full file name
    - Configurable suffix from settings (default `.secret.md`)
    - _Requirements: 5.1, 5.2_

  - [x] 12.2 Implement save hook (transparent encryption on save)
    - Create `src/hooks/save-hook.ts`: intercept `vault.on('modify')` for suffix-matching notes
    - Split frontmatter/body → encrypt body → serialize → atomic write (frontmatter + encrypted block)
    - Abort and leave file unchanged on any failure
    - _Requirements: 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 12.3 Implement open hook (transparent decryption on open)
    - Create `src/hooks/open-hook.ts`: detect encrypted files on open
    - Parse encrypted block → CryptoEngine.decrypt → present frontmatter + plaintext to editor
    - On failure: open in read-only view with error banner
    - _Requirements: 5.7, 5.8_

  - [ ]* 12.4 Write property test: Frontmatter Preservation (Property 10)
    - **Property 10: Frontmatter Preservation**
    - Create `tests/property/hooks/save-hook.property.test.ts`
    - Generator: random valid YAML frontmatter + random body
    - Assert: after transparent encryption, on-disk file contains original frontmatter as plaintext followed by encrypted block
    - **Validates: Requirements 5.3, 5.4, 5.5**

  - [ ]* 12.5 Write property test: Ciphertext Stability Under KMS Unavailability (Property 6)
    - **Property 6: Ciphertext Stability Under KMS Unavailability**
    - Add to `tests/property/hooks/save-hook.property.test.ts`
    - Generator: encrypted files on disk, simulate KMS network/auth/timeout failure
    - Assert: on-disk bytes remain byte-for-byte unchanged after open/view/save attempts
    - **Validates: Requirements 20.1, 20.2, 20.3**

- [x] 13. Phase 2 — Attachment handling and file encryption command
  - [x] 13.1 Implement attachment hook
    - Create `src/hooks/attachment-hook.ts`: register handling for `.enc.png`, `.enc.jpg`, `.enc.pdf`
    - Decrypt attachment → create Blob URL → track per-view lifecycle
    - Revoke Blob URL and release buffer when all referencing views close (within 5s)
    - Enforce 50 MB size limit
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [x] 13.2 Implement "Encrypt current file" command
    - Create `src/commands/encrypt-file.ts`: register command for command palette and file context menu
    - For notes: rename with suffix, encrypt body, atomic write
    - For attachments: rename with `.enc` prefix to extension, encrypt content, atomic write
    - Skip if already encrypted; rollback on failure
    - 30s KMS timeout for file encryption
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [ ]* 13.3 Write unit tests for attachment hook and encrypt-file command
    - Mock Obsidian vault adapter, mock KMS
    - Test: attachment decrypt → Blob URL created → view close → Blob revoked
    - Test: encrypt file → rename + content replacement atomic
    - Test: already encrypted → abort with notice
    - Test: failure → rollback to original state
    - _Requirements: 6.3, 6.5, 7.4, 7.5_

- [x] 14. Phase 2 — UI views and notices
  - [x] 14.1 Implement encrypted file read-only view
    - Create `src/ui/encrypted-view.ts`: custom Obsidian view for failed decryption
    - Display hex dump or base64 of raw on-disk content with error banner
    - _Requirements: 5.8_

  - [x] 14.2 Implement notice helpers
    - Create `src/ui/notices.ts`: helper functions for displaying Obsidian notices (≥5s) with error category
    - Consistent formatting across all error types
    - _Requirements: 1.6, 1.7, 1.8, 2.5, 2.6, 5.6, 5.8_

  - [x] 14.3 Wire Phase 2 hooks and commands into plugin main
    - Update `src/main.ts`: register save hook, open hook, attachment hook, encrypt-file command
    - Add "Encrypted note suffix" to settings tab
    - _Requirements: 5.1, 6.1, 7.1_

- [x] 15. Checkpoint — Phase 2 (MVP) complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 16. Phase 3 — Multi-provider KMS support
  - [ ] 16.1 Implement Azure Key Vault Adapter
    - Create `src/providers/azure-keyvault-adapter.ts`: implements `ProviderAdapter` using `@azure/keyvault-keys`
    - `generateDataKey`: generate local DEK + wrap via Azure
    - `wrapDek`/`unwrapDek`: Azure Key Vault wrap/unwrap operations
    - `validateAccess`: verify key accessibility
    - AbortController timeout, encryption context as custom metadata
    - _Requirements: 9.1, 9.2, 9.7_

  - [ ] 16.2 Implement Google Cloud KMS Adapter
    - Create `src/providers/gcp-kms-adapter.ts`: implements `ProviderAdapter` using `@google-cloud/kms`
    - Same interface contract as AWS adapter
    - AbortController timeout, encryption context as additional authenticated data
    - _Requirements: 9.1, 9.2, 9.7_

  - [ ]* 16.3 Write unit tests for Azure and GCP adapters
    - Mock respective SDK clients
    - Test successful wrap/unwrap flows, timeout, auth errors
    - _Requirements: 9.7_

- [ ] 17. Phase 3 — Per-folder Encrypted Vault Policies
  - [ ] 17.1 Implement policy resolver
    - Create `src/policies/policy-resolver.ts`: resolve which policy applies to a given file path
    - Longest prefix match for overlapping policies
    - Policy takes precedence over suffix rule
    - Reject duplicate folder paths with validation error
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

  - [ ]* 17.2 Write property test: Policy Resolution Determinism (Property 11)
    - **Property 11: Policy Resolution Determinism**
    - Create `tests/property/policies/policy-resolver.property.test.ts`
    - Generator: random policy sets + random file paths
    - Assert: single policy → that policy used; multiple → longest prefix wins; policy + suffix → policy wins
    - **Validates: Requirements 10.2, 10.3, 10.4**

  - [ ] 17.3 Update save/open hooks to use policy resolver
    - Modify `src/hooks/save-hook.ts` and `src/hooks/open-hook.ts` to check policy resolver before suffix matcher
    - Use policy's provider and CMK for encryption/decryption
    - _Requirements: 10.2, 10.3, 10.6_

- [ ] 18. Phase 3 — Key rotation command
  - [ ] 18.1 Implement rotation modal UI
    - Create `src/ui/rotation-modal.ts`: Obsidian modal for selecting target provider and CMK
    - List available providers, validate target CMK
    - _Requirements: 11.2, 11.5_

  - [ ] 18.2 Implement "Rotate CMK for current file" command
    - Create `src/commands/rotate-cmk.ts`: register command
    - Flow: unwrap DEK with current provider/CMK → re-wrap with target provider/CMK → atomic write (ciphertext + nonce unchanged)
    - Abort on unwrap failure, re-wrap failure, or user cancel
    - Zero DEK on any exit path
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [ ]* 18.3 Write property test: Key Rotation Preserves Ciphertext (Property 12)
    - **Property 12: Key Rotation Preserves Ciphertext**
    - Create `tests/property/commands/rotate-cmk.property.test.ts`
    - Generator: random encrypted files, random target CMK
    - Assert: after rotation, ciphertext and nonce bytes are byte-for-byte identical; only wrappedDek, providerId, cmkId changed
    - **Validates: Requirements 11.2**

- [ ] 19. Phase 3 — Settings UI for multi-provider and policies
  - [ ] 19.1 Extend settings tab for multi-provider configuration
    - Update `src/ui/settings-tab.ts`: add provider enable/disable toggles, CMK fields for Azure and GCP
    - Provider-specific validation for each CMK format
    - _Requirements: 9.1, 10.1_

  - [ ] 19.2 Implement Encrypted Vault Policy management UI
    - Add policy list to settings tab: folder path, provider selector, CMK input
    - Add/remove policies, validate no duplicate folder paths
    - _Requirements: 10.1, 10.5_

  - [ ] 19.3 Wire Phase 3 components into plugin main
    - Update `src/main.ts`: register Azure and GCP adapters, policy resolver, rotation command
    - Conditional SDK bundling based on enabled providers
    - _Requirements: 9.1, 16.3_

- [ ] 20. Final checkpoint — All phases complete
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each logical phase
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The project uses TypeScript with Vitest for testing and fast-check for property-based tests
- All crypto operations use WebCrypto API (no third-party cipher libraries)
- Provider SDKs are conditionally bundled based on build configuration

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["2.1", "2.3", "8.1", "8.3", "8.4", "8.5"] },
    { "id": 3, "tasks": ["2.2", "2.4", "3.1", "3.5", "8.2"] },
    { "id": 4, "tasks": ["3.2", "3.6", "5.1"] },
    { "id": 5, "tasks": ["3.3", "3.4", "5.2", "5.3"] },
    { "id": 6, "tasks": ["5.4", "6.1"] },
    { "id": 7, "tasks": ["6.2", "6.3", "6.4", "6.5", "6.6"] },
    { "id": 8, "tasks": ["9.1", "9.2", "12.1"] },
    { "id": 9, "tasks": ["9.3", "10.1", "10.2"] },
    { "id": 10, "tasks": ["10.3", "12.2", "12.3"] },
    { "id": 11, "tasks": ["12.4", "12.5", "13.1", "13.2"] },
    { "id": 12, "tasks": ["13.3", "14.1", "14.2"] },
    { "id": 13, "tasks": ["14.3"] },
    { "id": 14, "tasks": ["16.1", "16.2", "17.1"] },
    { "id": 15, "tasks": ["16.3", "17.2", "17.3"] },
    { "id": 16, "tasks": ["18.1", "18.2"] },
    { "id": 17, "tasks": ["18.3", "19.1", "19.2"] },
    { "id": 18, "tasks": ["19.3"] }
  ]
}
```
