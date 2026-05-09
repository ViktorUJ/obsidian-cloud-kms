#!/usr/bin/env node
/**
 * ocke-rekey — Re-encrypt vault with a new KMS key (key rotation / migration).
 *
 * Scans a vault directory, finds all encrypted blocks and binary files,
 * unwraps DEK with the old key, re-wraps with the new key.
 * Ciphertext is NOT re-encrypted — only the wrapped DEK changes (fast).
 *
 * Usage:
 *   node ocke-rekey.mjs <vault-path> --new-key <ARN> [--old-key <ARN>] [--dry-run]
 *
 * Options:
 *   --new-key <ARN>   ARN of the new KMS key to wrap DEKs with
 *   --old-key <ARN>   ARN of the old key (optional — auto-detected from files)
 *   --dry-run         Show what would be changed without modifying files
 *   --vault-name <N>  Vault name for encryption context
 *
 * Requirements:
 *   - Node.js >= 18
 *   - @aws-sdk/client-kms
 *   - AWS credentials with Decrypt on old key + Encrypt on new key
 *
 * Example (migrate to new AWS account):
 *   node ocke-rekey.mjs /path/to/vault \
 *     --new-key arn:aws:kms:eu-north-1:NEW_ACCOUNT:key/new-key-id \
 *     --vault-name my-vault
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { fromIni } from '@aws-sdk/credential-provider-ini';

// --- Args parsing ---

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help')) {
  console.log(`
ocke-rekey — Re-encrypt vault with a new KMS key

Usage:
  node ocke-rekey.mjs <vault-path> --new-key <ARN> [options]

Options:
  --new-key <ARN>     New KMS key ARN (required)
  --old-key <ARN>     Old KMS key ARN (optional, auto-detected)
  --vault-name <N>    Vault name for encryption context
  --dry-run           Show changes without modifying files
  --help              Show this help

Example:
  node ocke-rekey.mjs ./my-vault \\
    --new-key arn:aws:kms:eu-north-1:111122223333:key/new-key \\
    --vault-name my-vault
`);
  process.exit(0);
}

const vaultPath = args[0];
const newKeyIdx = args.indexOf('--new-key');
const oldKeyIdx = args.indexOf('--old-key');
const vaultNameIdx = args.indexOf('--vault-name');
const dryRun = args.includes('--dry-run');

const newKeyArn = newKeyIdx !== -1 ? args[newKeyIdx + 1] : null;
const oldKeyArn = oldKeyIdx !== -1 ? args[oldKeyIdx + 1] : null;
const vaultName = vaultNameIdx !== -1 ? args[vaultNameIdx + 1] : '';

if (!newKeyArn) {
  console.error('Error: --new-key is required');
  process.exit(1);
}

// --- OCKE Binary Parser/Serializer ---

function parseOckeHeader(data) {
  let offset = 0;
  if (data.length < 4 || Buffer.compare(data.slice(0, 4), Buffer.from('OCKE')) !== 0) return null;
  offset += 4;
  const version = data.readUInt16BE(offset); offset += 2;
  const pidLen = data[offset]; offset += 1;
  const providerId = data.slice(offset, offset + pidLen).toString('ascii'); offset += pidLen;
  const cmkLen = data.readUInt16BE(offset); offset += 2;
  const cmkId = data.slice(offset, offset + cmkLen).toString('utf-8'); offset += cmkLen;
  const wdekLen = data.readUInt16BE(offset); offset += 2;
  const wrappedDek = data.slice(offset, offset + wdekLen); offset += wdekLen;
  const nonce = data.slice(offset, offset + 12); offset += 12;
  const authTag = data.slice(offset, offset + 16); offset += 16;
  const ctLen = data.readUInt32BE(offset); offset += 4;
  const ciphertext = data.slice(offset, offset + ctLen);

  return {
    version, providerId, cmkId, wrappedDek, nonce, authTag, ciphertext,
    // For re-serialization
    pidLen, cmkLen, wdekLen, ctLen
  };
}

function serializeOcke(record, newCmkId, newWrappedDek) {
  const providerBuf = Buffer.from(record.providerId, 'ascii');
  const cmkBuf = Buffer.from(newCmkId, 'utf-8');

  const totalLen = 4 + 2 + 1 + providerBuf.length + 2 + cmkBuf.length + 2 + newWrappedDek.length + 12 + 16 + 4 + record.ciphertext.length;
  const out = Buffer.alloc(totalLen);
  let offset = 0;

  out.write('OCKE', offset); offset += 4;
  out.writeUInt16BE(record.version, offset); offset += 2;
  out[offset] = providerBuf.length; offset += 1;
  providerBuf.copy(out, offset); offset += providerBuf.length;
  out.writeUInt16BE(cmkBuf.length, offset); offset += 2;
  cmkBuf.copy(out, offset); offset += cmkBuf.length;
  out.writeUInt16BE(newWrappedDek.length, offset); offset += 2;
  newWrappedDek.copy(out, offset); offset += newWrappedDek.length;
  record.nonce.copy(out, offset); offset += 12;
  record.authTag.copy(out, offset); offset += 16;
  out.writeUInt32BE(record.ciphertext.length, offset); offset += 4;
  record.ciphertext.copy(out, offset);

  return out;
}

// --- KMS operations ---

function extractRegion(arn) {
  const parts = arn.split(':');
  return parts.length >= 4 ? parts[3] : 'us-east-1';
}

async function unwrapDek(wrappedDek, cmkId, encryptionContext) {
  const region = extractRegion(cmkId);
  const client = new KMSClient({ region, credentials: fromIni() });
  const resp = await client.send(new DecryptCommand({
    CiphertextBlob: wrappedDek,
    KeyId: cmkId,
    EncryptionContext: encryptionContext,
  }));
  return Buffer.from(resp.Plaintext);
}

async function wrapDek(dek, cmkId, encryptionContext) {
  const region = extractRegion(cmkId);
  const client = new KMSClient({ region, credentials: fromIni() });
  const resp = await client.send(new EncryptCommand({
    KeyId: cmkId,
    Plaintext: dek,
    EncryptionContext: encryptionContext,
  }));
  return Buffer.from(resp.CiphertextBlob);
}

// --- File scanning ---

function walkDir(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results.push(...walkDir(full));
    } else {
      results.push(full);
    }
  }
  return results;
}

// --- Main ---

async function main() {
  console.log(`Vault: ${vaultPath}`);
  console.log(`New key: ${newKeyArn}`);
  console.log(`Old key: ${oldKeyArn || '(auto-detect from files)'}`);
  console.log(`Dry run: ${dryRun}`);
  console.log('');

  const files = walkDir(vaultPath);
  let rekeyed = 0;
  let skipped = 0;
  let errors = 0;

  for (const filePath of files) {
    const relPath = relative(vaultPath, filePath);

    try {
      if (filePath.endsWith('.md')) {
        // Check for ````ocke-v1 blocks
        const content = readFileSync(filePath, 'utf-8');
        const pattern = /````ocke-v1\n([\s\S]*?)\n````/g;
        const matches = [...content.matchAll(pattern)];

        if (matches.length === 0) { skipped++; continue; }

        let newContent = content;
        for (const match of matches) {
          const b64 = match[1].trim().replace(/\s/g, '');
          const bin = Buffer.from(b64, 'base64');
          const record = parseOckeHeader(bin);
          if (!record) continue;

          // Skip if already using new key
          if (record.cmkId === newKeyArn) continue;

          // Skip if old key specified and doesn't match
          if (oldKeyArn && record.cmkId !== oldKeyArn) continue;

          const ctx = { vaultName, filePath: relPath, formatVersion: String(record.version) };

          if (dryRun) {
            console.log(`  [DRY] ${relPath}: block ${record.cmkId} → ${newKeyArn}`);
            rekeyed++;
            continue;
          }

          // Unwrap with old key, re-wrap with new key
          const dek = await unwrapDek(record.wrappedDek, record.cmkId, ctx);
          const newWrappedDek = await wrapDek(dek, newKeyArn, ctx);
          dek.fill(0); // Zero DEK

          // Re-serialize with new cmkId and wrappedDek
          const newBin = serializeOcke(record, newKeyArn, newWrappedDek);
          const newB64 = newBin.toString('base64');
          const newBlock = '````ocke-v1\n' + newB64 + '\n````';
          newContent = newContent.replace(match[0], newBlock);
          rekeyed++;
        }

        if (!dryRun && newContent !== content) {
          writeFileSync(filePath, newContent, 'utf-8');
          console.log(`  ✓ ${relPath} (${matches.length} block(s))`);
        }

      } else {
        // Binary file — check for OCKE magic
        const data = readFileSync(filePath);
        if (data.length < 4 || data[0] !== 0x4F || data[1] !== 0x43 || data[2] !== 0x4B || data[3] !== 0x45) {
          skipped++;
          continue;
        }

        const record = parseOckeHeader(data);
        if (!record) { skipped++; continue; }

        // Skip if already using new key
        if (record.cmkId === newKeyArn) { skipped++; continue; }

        // Skip if old key specified and doesn't match
        if (oldKeyArn && record.cmkId !== oldKeyArn) { skipped++; continue; }

        const ctx = { vaultName, filePath: relPath, formatVersion: String(record.version) };

        if (dryRun) {
          console.log(`  [DRY] ${relPath}: ${record.cmkId} → ${newKeyArn}`);
          rekeyed++;
          continue;
        }

        // Unwrap with old key, re-wrap with new key
        const dek = await unwrapDek(record.wrappedDek, record.cmkId, ctx);
        const newWrappedDek = await wrapDek(dek, newKeyArn, ctx);
        dek.fill(0);

        const newBin = serializeOcke(record, newKeyArn, newWrappedDek);
        writeFileSync(filePath, newBin);
        console.log(`  ✓ ${relPath} (binary)`);
        rekeyed++;
      }
    } catch (err) {
      console.error(`  ✗ ${relPath}: ${err.message}`);
      errors++;
    }
  }

  console.log('');
  console.log(`Done. Re-keyed: ${rekeyed}, Skipped: ${skipped}, Errors: ${errors}`);

  if (dryRun) {
    console.log('(Dry run — no files were modified)');
  }
}

main().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
