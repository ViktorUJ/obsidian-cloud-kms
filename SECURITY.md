# Security Policy

## Threat Model

### What this plugin protects against

| Threat | Protection |
|--------|-----------|
| Unauthorized access to vault storage (S3, Git, cloud sync) | ✅ Ciphertext-only on disk |
| Stolen laptop with powered-off device | ✅ Encrypted at rest |
| CloudTrail audit of who accessed secrets | ✅ Every KMS unwrap is logged |
| Accidental commit of secrets to Git | ✅ Only ciphertext in repo |
| Unauthorized KMS access | ✅ IAM policies + key policies |

### What this plugin does NOT protect against

| Threat | Reason |
|--------|--------|
| Malicious Obsidian plugin in same vault | Obsidian has no plugin sandbox — any plugin can read editor memory |
| Memory dump / cold boot attack | Plaintext exists in JS heap during editing session |
| Compromised workstation with active session | Attacker has same access as user |
| Keylogger / screen capture | Out of scope — OS-level threat |
| State-level adversary | Use dedicated HSM + isolated workstation instead |

### Trust boundaries

```
┌─────────────────────────────────────────────────┐
│  Obsidian Process (Electron)                     │
│  ┌───────────────────────────────────────────┐  │
│  │  Plugin Runtime (no sandbox)               │  │
│  │  - Plaintext in editor buffer              │  │
│  │  - DEK in memory (briefly)                 │  │
│  │  - Blob URLs for binary files              │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  Other plugins (untrusted)                 │  │
│  │  - Can access DOM, editor, filesystem      │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
         │ write (encrypted)    │ read (encrypted)
         ▼                      ▼
┌─────────────────────────────────────────────────┐
│  Disk / Cloud Storage                            │
│  - Only ciphertext                               │
│  - OCKE binary format or ````ocke-v1 base64     │
└─────────────────────────────────────────────────┘
         │ KMS Decrypt/GenerateDataKey
         ▼
┌─────────────────────────────────────────────────┐
│  AWS KMS                                         │
│  - CMK never leaves KMS                          │
│  - All operations logged in CloudTrail           │
│  - IAM + Key Policy access control               │
└─────────────────────────────────────────────────┘
```

## Cryptographic Design

### Envelope Encryption

Each secret block or binary file is encrypted with a unique Data Encryption Key (DEK):

1. **GenerateDataKey** → KMS returns plaintext DEK + wrapped DEK
2. **Encrypt** → AES-256-GCM(plaintext, DEK, nonce) → ciphertext + auth tag
3. **Store** → wrapped DEK + nonce + auth tag + ciphertext (DEK is zeroed)
4. **Decrypt** → KMS unwraps DEK → AES-256-GCM decrypt → plaintext (DEK is zeroed)

### Primitives

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Symmetric cipher | AES-256-GCM | AEAD, hardware-accelerated, WebCrypto native |
| Nonce | 96-bit random | crypto.getRandomValues(), unique per encryption |
| Auth tag | 128-bit | GCM default, tamper detection |
| Key wrap | AWS KMS | HSM-backed, auditable, IAM-controlled |
| DEK size | 256-bit | AES-256 key length |
| Key derivation | None (KMS generates DEK directly) | No custom KDF needed |

### What we explicitly avoid

- ❌ Custom cryptographic algorithms
- ❌ CBC mode (no authentication)
- ❌ Deterministic IVs/nonces
- ❌ Hardcoded salts or keys
- ❌ Password-based encryption (PBKDF2, scrypt)
- ❌ Client-side key storage

## Memory Handling

### Secure cleanup

- `SecureBuffer` class: zero-fills buffer on release
- DEK zeroed immediately after encrypt/decrypt operation
- Blob URLs revoked on plugin unload
- LRU cache evicts old decrypted binary files (max 20)

### Known limitations

- JavaScript garbage collector may retain copies of plaintext
- Obsidian undo buffer contains decrypted text
- Electron renderer process holds editor state in memory
- OS swap/pagefile may contain memory pages with plaintext

## Credential Handling

### How credentials are loaded

```
AWS SDK credential chain:
1. ~/.aws/credentials (fromIni)
2. AWS SSO session
3. IAM instance role (EC2/ECS)
4. Environment variables
```

### What is NOT stored by the plugin

- ❌ AWS access keys
- ❌ AWS secret keys
- ❌ Session tokens
- ❌ Any credential material

### What IS stored in plugin settings

- ✅ KMS Key ARN (not a secret — it's a resource identifier)
- ✅ User preferences (auto-decrypt toggle, suffix)

## Logging

- Structured JSON logs via `structured-logger.ts`
- Sanitizer strips sensitive fields before logging
- No plaintext, DEK, or credential values in logs
- Only metadata: provider, file path, payload size, timing

## Supply Chain

- Dependencies pinned in `package-lock.json`
- `npm audit` runs in CI on every push
- Reproducible builds via Docker (`make docker-release`)
- No telemetry, no analytics, no network calls except to AWS KMS

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately:

- Email: viktoruj@gmail.com
- Do NOT open a public GitHub issue for security vulnerabilities
- I will respond within 48 hours and work on a fix

## Recommended Usage

### Good fit

- Personal API keys and tokens
- Terraform/infrastructure secrets
- Internal documentation with sensitive data
- Developer secret workflows (similar to SOPS/git-crypt)
- Team knowledge bases with access-controlled secrets

### Consider alternatives for

- Production root credentials → use AWS Secrets Manager / HashiCorp Vault
- Regulated data (HIPAA, PCI-DSS) → use certified solutions with compliance attestation
- State-level adversary threat model → use hardware-backed auth + isolated workstation
