#!/usr/bin/env node
/**
 * Submit plugin to obsidian-releases community-plugins.json
 */
import { execSync } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';

// Get current file content
const raw = execSync(
  'gh api repos/ViktorUJ/obsidian-releases/contents/community-plugins.json -H "Accept: application/vnd.github.raw"',
  { maxBuffer: 10 * 1024 * 1024 }
).toString();

const json = JSON.parse(raw);

// Check if already exists
if (json.some(p => p.id === 'obsidian-cloud-kms-encryption')) {
  console.log('Plugin already exists in community-plugins.json');
  process.exit(0);
}

// Add our plugin
json.push({
  id: 'obsidian-cloud-kms-encryption',
  name: 'Cloud KMS Encryption',
  author: 'ViktorUJ',
  description: 'Transparent encryption of secret blocks and binary files using AWS KMS. Zero plaintext on disk.',
  repo: 'ViktorUJ/obsidian-cloud-kms'
});

// Encode
const newContent = JSON.stringify(json, null, 2) + '\n';
const encoded = Buffer.from(newContent).toString('base64');

// Get file SHA
const shaOutput = execSync(
  'gh api repos/ViktorUJ/obsidian-releases/contents/community-plugins.json --jq .sha'
).toString().trim();

// Push to branch
const body = JSON.stringify({
  message: 'Add Cloud KMS Encryption plugin',
  content: encoded,
  sha: shaOutput,
  branch: 'add-cloud-kms-encryption'
});

writeFileSync('/tmp/submit-body.json', body);

try {
  execSync('gh api repos/ViktorUJ/obsidian-releases/contents/community-plugins.json -X PUT --input /tmp/submit-body.json', { stdio: 'pipe' });
  console.log('File updated on branch add-cloud-kms-encryption');
} catch (e) {
  console.error('Error updating file:', e.stderr?.toString() || e.message);
  process.exit(1);
} finally {
  try { unlinkSync('/tmp/submit-body.json'); } catch {}
}

// Create PR
try {
  const prBody = `## Plugin submission: Cloud KMS Encryption

- **Plugin ID:** obsidian-cloud-kms-encryption
- **Repo:** https://github.com/ViktorUJ/obsidian-cloud-kms
- **Description:** Transparent envelope encryption of secret blocks and binary files using AWS KMS (AES-256-GCM + KMS DEK wrap). Zero plaintext on disk.
- **Desktop only:** yes
- **License:** MIT

### Features
- Transparent encrypt-on-write / decrypt-on-read via vault adapter patch
- Multi-key support with aliases (per-team access control)
- Binary file encryption (PDF, images, audio)
- Pre-commit hook for plaintext leak protection
- CLI tools for disaster recovery
- SLSA Level 2 provenance, Cosign signed releases, SBOM
- OpenSSF Scorecard monitored`;

  writeFileSync('/tmp/pr-body.md', prBody);
  const result = execSync(
    'gh pr create --repo obsidianmd/obsidian-releases --head ViktorUJ:add-cloud-kms-encryption --base master --title "Add Cloud KMS Encryption plugin" --body-file /tmp/pr-body.md',
    { stdio: 'pipe' }
  ).toString();
  console.log('PR created:', result.trim());
  unlinkSync('/tmp/pr-body.md');
} catch (e) {
  console.error('Error creating PR:', e.stderr?.toString() || e.message);
}
