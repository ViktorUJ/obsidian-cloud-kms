# Security Testing Documentation

## Overview

This document describes the security testing approach for the obsidian-cloud-kms-encryption plugin. It covers what is tested, how, and what remains untested.

## Test Categories

### 1. Unit Tests (357 tests)

Automated tests covering individual components:

| Component | Tests | What's verified |
|-----------|-------|-----------------|
| SecureBuffer | 8 | Zero-fill on release, access-after-release throws, double-release safe |
| BufferRegistry | 6 | Tracking, force-release-all, cleanup on unload |
| WebCrypto (AES-256-GCM) | 12 | Encrypt/decrypt round-trip, auth tag verification, nonce uniqueness |
| CryptoEngine | 15 | Envelope encryption flow, DEK zeroing, error propagation |
| OCKE Parser | 24 | Magic bytes, version check, field validation, truncation detection, trailing bytes |
| OCKE Serializer | 18 | Round-trip, field constraints, big-endian encoding |
| Inline Codec | 12 | Base64 encode/decode, fence detection, whitespace handling |
| AWS KMS Adapter | 14 | Timeout, credential errors, authorization errors, region extraction |
| Provider Dispatcher | 10 | Registration, duplicate rejection, interface validation |
| ARN Validator | 16 | Format validation, edge cases, region extraction |
| Frontmatter Splitter | 18 | YAML detection, body extraction, edge cases |
| Suffix Matcher | 25 | Case-sensitive matching, empty inputs |
| Settings Tab | 9 | Default values, persistence, validation |
| Notices | 6 | Error category display |
| Structured Logger | 8 | JSON output, sanitization |
| Sanitizer | 12 | Sensitive field stripping |

### 2. Fuzz Testing (CI workflow)

Weekly automated fuzzing:
- Random byte sequences fed to OCKE parser (crash detection)
- Property-based tests via fast-check (when property tests exist)
- Ensures no unhandled exceptions on malformed input

### 3. Static Analysis (CodeQL)

Automated SAST on every push:
- SQL injection patterns
- Path traversal
- Hardcoded secrets
- Insecure crypto usage
- Prototype pollution
- Command injection

### 4. Dependency Scanning

- `npm audit` on every CI run (high + critical)
- Dependabot weekly updates
- SBOM generated per release

## Security Properties Verified

| Property | How verified | Status |
|----------|-------------|--------|
| Encrypt/decrypt round-trip | Unit tests + property tests | ✅ |
| Auth tag detects tampering | Unit test (flip byte → error) | ✅ |
| DEK zeroed after use | Unit test (buffer state check) | ✅ |
| No plaintext in serialized output | Unit test (substring search) | ✅ |
| Parser rejects malformed input | Unit tests (24 cases) | ✅ |
| Nonce never reused | Unit test (uniqueness check) | ✅ |
| Credentials not stored | Code review + no localStorage usage | ✅ |
| No sensitive data in logs | Sanitizer unit tests | ✅ |
| Timeout enforcement | Unit test (AbortController) | ✅ |
| Graceful degradation on KMS failure | Unit test (error handling) | ✅ |

## What Is NOT Tested

| Area | Reason | Risk |
|------|--------|------|
| Actual KMS integration | Requires live AWS account | Tested manually |
| Obsidian API compatibility | Requires running Obsidian | Tested manually |
| Memory leak detection | No automated tooling for JS heap | Low (SecureBuffer mitigates) |
| Side-channel attacks | Out of scope for JS runtime | Accept |
| Concurrent access | Obsidian is single-threaded | N/A |
| Cross-plugin interference | Cannot simulate in unit tests | Documented limitation |

## Running Security Tests

```bash
# Full test suite
npm test

# Only security-relevant tests
npx vitest --run tests/unit/core/
npx vitest --run tests/unit/format/
npx vitest --run tests/unit/providers/

# Lint for security patterns
npx eslint src/ --rule '{"no-eval": "error", "no-implied-eval": "error"}'

# Dependency audit
npm audit --audit-level=high

# Type safety (catches many security bugs)
npx tsc --noEmit
```

## Verification Checklist (for reviewers)

- [ ] No `eval()`, `Function()`, or `new Function()` in source
- [ ] No `console.log` with sensitive data in production code
- [ ] No credentials in settings or localStorage
- [ ] All crypto uses WebCrypto API (no custom implementations)
- [ ] DEK buffers zeroed in all code paths (success + error)
- [ ] No plaintext written to any file (adapter patch intercepts)
- [ ] Error messages don't contain plaintext or DEK material
- [ ] All KMS calls have timeout (AbortController)
- [ ] Blob URLs revoked on plugin unload
