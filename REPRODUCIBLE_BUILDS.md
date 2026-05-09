# Reproducible Builds

## Overview

This project supports reproducible builds — you can independently verify that the `main.js` in a GitHub Release was built from the exact source code in the repository, without any tampering.

## Why This Matters

- **Trust:** You don't have to trust the maintainer — verify yourself
- **Supply chain:** Detects if CI was compromised or artifacts were modified post-build
- **Compliance:** Proves artifact provenance for enterprise environments

## How to Verify a Release

### Method 1: Rebuild and Compare Hash

```bash
# 1. Check out the exact commit for the release
git clone https://github.com/ViktorUJ/obsidian-cloud-kms.git
cd obsidian-cloud-kms
git checkout v0.1.1  # replace with release tag

# 2. Build in Docker (deterministic environment)
make docker-release

# 3. Compare hash with the released artifact
sha256sum dist/main.js
# Compare with the hash from the release

# 4. Download the release artifact and compare
gh release download v0.1.1 --pattern "main.js" --dir /tmp/release
sha256sum /tmp/release/main.js

# If hashes match → the release was built from this exact source
```

### Method 2: Use Docker for Exact Reproduction

```bash
# Build using the same Docker image as CI
docker build -t obsidian-cloud-kms-builder .
docker run --rm -v $(pwd):/app -w /app obsidian-cloud-kms-builder make release

# The output in dist/ should be byte-for-byte identical to the release
sha256sum dist/main.js
```

### Method 3: Verify SLSA Provenance (Recommended)

The easiest way — GitHub cryptographically attests that the artifact was built from this repo:

```bash
# Download the release artifact
gh release download v0.1.1 --pattern "main.js" --dir /tmp/verify

# Verify provenance (proves it was built in GitHub Actions from this repo)
gh attestation verify /tmp/verify/main.js --repo ViktorUJ/obsidian-cloud-kms
```

Output on success:
```
✓ Verification succeeded!
  Repository: ViktorUJ/obsidian-cloud-kms
  Workflow: .github/workflows/ci.yml
```

### Method 4: Verify Cosign Signature

```bash
# Download artifact + signature bundle
gh release download v0.1.1 --pattern "main.js" --pattern "main.js.bundle" --dir /tmp/verify

# Verify signature
cosign verify-blob /tmp/verify/main.js \
  --bundle /tmp/verify/main.js.bundle \
  --certificate-identity-regexp "github.com/ViktorUJ/obsidian-cloud-kms" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Build Environment

| Component | Version | Source |
|-----------|---------|--------|
| Node.js | 20.x | `actions/setup-node` in CI |
| npm | Bundled with Node.js | `npm ci` from lockfile |
| esbuild | Pinned in package.json | Deterministic bundler |
| OS | Ubuntu 24.04 | GitHub Actions runner |
| Docker | node:20-alpine | `Dockerfile` in repo |

## Determinism Notes

### What makes builds reproducible

- `npm ci` installs exact versions from `package-lock.json`
- esbuild produces deterministic output for same input
- No timestamps or random values in build output
- Docker provides consistent OS environment

### Known sources of non-determinism

- **Minification:** esbuild minification is deterministic for same version, but different esbuild versions may produce different output
- **Source maps:** Disabled in production builds (`sourcemap: false`)
- **Node.js version:** Minor version differences may affect bundled polyfills

### Mitigation

Pin all build tools to exact versions:
- `esbuild`: exact version in `package.json`
- `Node.js`: exact version in CI workflow
- `npm`: comes with Node.js (deterministic for same Node version)

## CI Build Pipeline

```
Source code (git tag)
    │
    ▼
npm ci (exact deps from lockfile)
    │
    ▼
make release
    │
    ├── typecheck (tsc --noEmit)
    ├── lint (eslint)
    ├── test (vitest)
    └── build (esbuild production)
            │
            ▼
      dist/main.js ← this is the release artifact
            │
            ├── SLSA attestation (signed provenance)
            ├── Cosign signature (signed blob)
            ├── SBOM (dependency list)
            └── GitHub Release (published)
```

## For Auditors

To verify the complete supply chain:

1. **Source:** Single commit on `main` branch, signed by GitHub
2. **Dependencies:** `package-lock.json` with integrity hashes (SHA-512)
3. **Build:** Deterministic esbuild, reproducible in Docker
4. **Artifact:** SLSA Level 2 provenance + Cosign signature
5. **Distribution:** GitHub Releases (immutable after publish)
