# Security Policy

## Threat Model

### Attacker Model

| Attacker | Capability | Access Level |
|----------|-----------|--------------|
| Cloud storage attacker | Has encrypted blobs only (S3 breach, Git repo leak) | Ciphertext only |
| Credential thief | Has stolen IAM credentials | Can call KMS if IAM allows |
| Local malware | Has filesystem access on user's machine | Can read encrypted files + potentially memory |
| Malicious Obsidian plugin | Has full Obsidian API access (DOM, editor, filesystem) | Can read decrypted content in editor |
| Network attacker (MITM) | Can intercept network traffic | TLS protects KMS calls |
| Physical access (powered off) | Has the device but no running session | Ciphertext only on disk |
| Physical access (powered on) | Has the device with active Obsidian session | Full access to decrypted content |

### Asset Classification

**Fully protected (encrypted at rest):**
- Note body content (inside `%%secret-start%%` blocks)
- Binary file content (PDF, images, audio)
- Data Encryption Keys (wrapped by KMS, zeroed after use)

**Partially protected:**
- File names (visible on disk, not encrypted)
- File timestamps (visible on disk)
- Vault structure / folder names (visible)
- Frontmatter metadata (visible, for Obsidian indexing)

**Not protected by this plugin:**
- AWS credentials (managed by OS/AWS CLI)
- Plugin settings (KMS key ARN — not a secret)
- Obsidian workspace state

### Security Assumptions

```
Assumes:
  - Secure WebCrypto API implementation (browser/Electron engine)
  - Uncompromised operating system and kernel
  - Correct AWS IAM configuration (least privilege)
  - TLS integrity for KMS API calls (AWS SDK handles this)
  - No malicious Obsidian plugins installed in the same vault
  - User does not disable the plugin and save files with secret markers
```

### Threat → Mitigation Matrix

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Stolen cloud storage (S3/Git) | Envelope encryption (AES-256-GCM + KMS) | None — ciphertext only |
| Man-in-the-middle | TLS (AWS SDK) + AEAD (GCM auth tag) | None |
| Ciphertext tampering | AES-256-GCM authentication tag | None — tamper detected |
| Key exposure | CMK never leaves AWS KMS HSM | None |
| DEK exposure in memory | Zero-fill after use, no caching | GC copies (JS limitation) |
| Replay / DEK reuse | Fresh random DEK + nonce per operation | None |
| Unauthorized decryption | IAM policies + KMS key policies + CloudTrail | Misconfiguration risk |
| Plugin disabled during save | Pre-commit hook blocks plaintext commits | User must install hook |
| KMS unavailable | Status bar indicator + graceful degradation | Plaintext in editor only (not on disk if plugin active) |
| Malicious plugin reads editor | No mitigation (Obsidian platform limitation) | Accept — documented |
| Memory dump | SecureBuffer zero-fill on release | JS heap copies (accept) |
| Supply chain attack | Pinned deps, SBOM, Scorecard, signed releases | Transitive dep risk remains |

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

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  User's Workstation                                              │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Obsidian Process (Electron)                               │  │
│  │                                                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  Cloud KMS Plugin (this plugin)                      │  │  │
│  │  │  - Plaintext in editor buffer (TRUSTED)              │  │  │
│  │  │  - DEK in memory briefly (TRUSTED)                   │  │  │
│  │  │  - Blob URLs for binary files (TRUSTED)              │  │  │
│  │  │  - Adapter patch intercepts read/write               │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  Other Obsidian Plugins (UNTRUSTED)                  │  │  │
│  │  │  - Can access: DOM, editor API, filesystem           │  │  │
│  │  │  - Can read: decrypted content in editor             │  │  │
│  │  │  - Cannot access: KMS credentials directly           │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Local Filesystem (UNTRUSTED for plaintext)                │  │
│  │  - Only ciphertext written                                 │  │
│  │  - OCKE binary format / ````ocke-v1 base64                │  │
│  │  - File names and timestamps visible                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  OS Credential Store (~/.aws/credentials)                  │  │
│  │  - Managed by AWS CLI / SSO                                │  │
│  │  - Plugin reads, never writes                              │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                    │                           │
                    │ TLS (HTTPS)               │ git push (ciphertext)
                    ▼                           ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│  AWS KMS (TRUSTED)            │  │  Remote Storage (UNTRUSTED)   │
│  - CMK in HSM                 │  │  - S3 / Git / Cloud Sync      │
│  - Never exports key material │  │  - Only ciphertext             │
│  - All ops in CloudTrail      │  │  - No access to plaintext      │
│  - IAM + Key Policy           │  │                                │
└──────────────────────────────┘  └──────────────────────────────┘
```

### Cryptographic Flow

```
ENCRYPTION (on file write):
  ┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────┐
  │ Plaintext │────▶│ Generate │────▶│ AES-256-GCM  │────▶│Ciphertext│
  │  (editor) │     │ DEK+Nonce│     │ Encrypt      │     │ + AuthTag│
  └──────────┘     └────┬─────┘     └──────────────┘     └──────────┘
                         │
                         ▼
                   ┌──────────┐     ┌──────────────┐
                   │   DEK    │────▶│  KMS Encrypt │────▶ Wrapped DEK
                   │(plaintext)│     │  (wrap)      │     (safe to store)
                   └──────────┘     └──────────────┘
                         │
                         ▼
                   Zero-fill DEK

DECRYPTION (on file read):
  ┌───────────┐     ┌──────────────┐     ┌──────────┐
  │Wrapped DEK│────▶│  KMS Decrypt │────▶│   DEK    │
  │(from disk) │     │  (unwrap)    │     │(plaintext)│
  └───────────┘     └──────────────┘     └────┬─────┘
                                               │
  ┌──────────┐     ┌──────────────┐           │
  │Ciphertext│────▶│ AES-256-GCM  │◀──────────┘
  │ + AuthTag│     │ Decrypt+Verify│
  └──────────┘     └──────┬───────┘
                           │
                           ▼
                     ┌──────────┐
                     │ Plaintext │────▶ Editor (memory only)
                     └──────────┘
                           │
                     Zero-fill DEK
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

## Secure Deployment Recommendations

### Dedicated Vault for Secrets

For maximum security, use a **separate Obsidian vault** for encrypted content:

```
~/vaults/
├── work/              ← General notes, many plugins installed
├── personal/          ← Personal notes
└── secrets/           ← Encrypted vault (minimal plugins)
```

**Why:** Other plugins in the same vault can read decrypted content from the editor. A dedicated vault minimizes this attack surface.

### Minimal Plugin Configuration

In the encrypted vault, install only:
- This plugin (Cloud KMS Encryption)
- Essential plugins you trust (e.g., built-in plugins only)

**Avoid** in the encrypted vault:
- Community plugins with network access
- Plugins that sync content to external services
- Plugins that read/modify file content
- Plugins from unknown/unverified authors

### Workstation Hardening

| Measure | Purpose |
|---------|---------|
| Full-disk encryption (BitLocker/FileVault) | Protects swap/pagefile containing memory pages |
| Screen lock on idle | Prevents physical access to active session |
| Disable swap/pagefile (if RAM allows) | Eliminates plaintext in swap |
| Use AWS SSO with short-lived tokens | Limits credential exposure window |
| Enable MFA on AWS account | Prevents credential theft from granting KMS access |
| Regular `aws sso logout` when done | Invalidates cached session |

### Network Security

| Measure | Purpose |
|---------|---------|
| VPN for KMS access | Ensures connectivity, prevents MITM on corporate networks |
| AWS VPC PrivateLink for KMS | Eliminates internet dependency for KMS calls |
| DNS-over-HTTPS | Prevents DNS-based traffic analysis |

### Monitoring

| What to monitor | How |
|-----------------|-----|
| KMS Decrypt calls | CloudTrail → CloudWatch alarm on unusual patterns |
| Failed KMS auth | CloudTrail → alert on AccessDeniedException |
| New IAM grants on KMS key | AWS Config rule |
| Plugin status indicator | Visual check: 🔓 = OK, 🔒 ⚠️ = problem |

### Incident Response

If you suspect compromise:

1. **Immediately:** `aws sso logout` or rotate IAM credentials
2. **Assess:** Check CloudTrail for unauthorized KMS Decrypt calls
3. **Contain:** Disable KMS key if unauthorized access confirmed (`aws kms disable-key`)
4. **Recover:** Re-enable key after investigation, rotate if needed (`tools/ocke-rekey.mjs`)
5. **Prevent:** Review IAM policies, enable MFA, audit plugin list
