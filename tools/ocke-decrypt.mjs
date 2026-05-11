#!/usr/bin/env node
/**
 * ocke-decrypt — Node.js CLI tool for decrypting OCKE encrypted files/blocks.
 *
 * Usage:
 *   node ocke-decrypt.mjs <file>              # Decrypt and print to stdout
 *   node ocke-decrypt.mjs <file> -o <output>  # Decrypt and write to file
 *
 * Environment:
 *   OCKE_VAULT_NAME  — vault name for encryption context (optional)
 *   AWS_REGION       — fallback region (auto-detected from ARN)
 *
 * Requirements:
 *   - Node.js >= 18
 *   - AWS credentials configured (~/.aws/credentials or env vars)
 *   - @aws-sdk/client-kms (installed via: npm install @aws-sdk/client-kms)
 *
 * Install globally:
 *   npm install -g @aws-sdk/client-kms
 *   # Then run: node ocke-decrypt.mjs <file>
 */

import { readFileSync, writeFileSync } from 'fs';
import { createDecipheriv } from 'crypto';
import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import { fromIni } from '@aws-sdk/credential-provider-ini';

// --- OCKE Binary Parser ---

function parseOckeBinary(data) {
  let offset = 0;

  // Magic (4 bytes)
  const magic = data.slice(offset, offset + 4);
  if (Buffer.compare(magic, Buffer.from('OCKE')) !== 0) return null;
  offset += 4;

  // Version (uint16 BE)
  const version = data.readUInt16BE(offset);
  offset += 2;

  // ProviderIdLen (1 byte) + ProviderId
  const providerIdLen = data[offset];
  offset += 1;
  const providerId = data.slice(offset, offset + providerIdLen).toString('ascii');
  offset += providerIdLen;

  // CmkIdLen (uint16 BE) + CmkId
  const cmkIdLen = data.readUInt16BE(offset);
  offset += 2;
  const cmkId = data.slice(offset, offset + cmkIdLen).toString('utf-8');
  offset += cmkIdLen;

  // WrappedDekLen (uint16 BE) + WrappedDek
  const wrappedDekLen = data.readUInt16BE(offset);
  offset += 2;
  const wrappedDek = data.slice(offset, offset + wrappedDekLen);
  offset += wrappedDekLen;

  // Nonce (12 bytes)
  const nonce = data.slice(offset, offset + 12);
  offset += 12;

  // AuthTag (16 bytes)
  const authTag = data.slice(offset, offset + 16);
  offset += 16;

  // CiphertextLen (uint32 BE) + Ciphertext
  const ciphertextLen = data.readUInt32BE(offset);
  offset += 4;
  const ciphertext = data.slice(offset, offset + ciphertextLen);

  return { version, providerId, cmkId, wrappedDek, nonce, authTag, ciphertext };
}

function extractRegionFromArn(arn) {
  const parts = arn.split(':');
  if (parts.length >= 6 && parts[0] === 'arn' && parts[2] === 'kms') {
    return parts[3];
  }
  return process.env.AWS_REGION || 'us-east-1';
}

async function kmsDecrypt(wrappedDek, cmkId, encryptionContext) {
  const region = extractRegionFromArn(cmkId);
  const client = new KMSClient({ region, credentials: fromIni() });

  const command = new DecryptCommand({
    CiphertextBlob: wrappedDek,
    KeyId: cmkId,
    EncryptionContext: encryptionContext,
  });

  const response = await client.send(command);
  return Buffer.from(response.Plaintext);
}

function aesGcmDecrypt(key, nonce, ciphertext, authTag) {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
}

async function decryptRecord(record, filePath, vaultName) {
  const encryptionContext = {
    vaultName: vaultName || '',
    filePath: filePath || '',
    formatVersion: String(record.version),
  };

  // Unwrap DEK via KMS
  const dek = await kmsDecrypt(record.wrappedDek, record.cmkId, encryptionContext);

  // Decrypt content via AES-256-GCM
  return aesGcmDecrypt(dek, record.nonce, record.ciphertext, record.authTag);
}

// --- Main ---

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: node ocke-decrypt.mjs <file> [-o output] [--vault-name NAME] [--file-path PATH]');
    console.error('');
    console.error('Decrypts OCKE encrypted content (markdown blocks or binary files).');
    console.error('');
    console.error('Options:');
    console.error('  -o <file>           Write output to file instead of stdout');
    console.error('  --vault-name NAME   Vault name for encryption context');
    console.error('  --file-path PATH    File path for encryption context (vault-relative)');
    console.error('');
    console.error('Environment (alternative to flags):');
    console.error('  OCKE_VAULT_NAME     Vault name for encryption context');
    console.error('  OCKE_FILE_PATH      File path for encryption context');
    console.error('');
    console.error('Requirements: Node.js >= 18, @aws-sdk/client-kms');
    console.error('  npm install @aws-sdk/client-kms @aws-sdk/credential-provider-ini');
    process.exit(1);
  }

  const inputFile = args[0];
  const outputIdx = args.indexOf('-o');
  const outputFile = outputIdx !== -1 ? args[outputIdx + 1] : null;

  const vaultNameIdx = args.indexOf('--vault-name');
  const filePathIdx = args.indexOf('--file-path');

  const vaultName = vaultNameIdx !== -1 ? args[vaultNameIdx + 1] : (process.env.OCKE_VAULT_NAME || '');
  const filePath = filePathIdx !== -1 ? args[filePathIdx + 1] : (process.env.OCKE_FILE_PATH || inputFile.split('/').pop().split('\\').pop());

  const rawData = readFileSync(inputFile);

  // Check if binary OCKE file
  if (rawData.length >= 4 && rawData.slice(0, 4).toString() === 'OCKE') {
    const record = parseOckeBinary(rawData);
    if (!record) {
      console.error('Error: Failed to parse OCKE binary format');
      process.exit(1);
    }

    const plaintext = await decryptRecord(record, filePath, vaultName);

    if (outputFile) {
      writeFileSync(outputFile, plaintext);
      console.error(`Decrypted: ${inputFile} -> ${outputFile}`);
    } else {
      process.stdout.write(plaintext);
    }
    return;
  }

  // Text file — look for ````ocke-v1 blocks
  const text = rawData.toString('utf-8');
  const pattern = /````ocke-v1\n([\s\S]*?)\n````/g;

  const matches = [...text.matchAll(pattern)];
  if (matches.length === 0) {
    console.error('No encrypted blocks found in file');
    process.exit(1);
  }

  let result = text;
  for (const match of matches) {
    const b64Content = match[1].trim().replace(/\s/g, '');
    const binaryData = Buffer.from(b64Content, 'base64');
    const record = parseOckeBinary(binaryData);

    if (!record) continue;

    try {
      const plaintext = await decryptRecord(record, filePath, vaultName);
      const plaintextText = plaintext.toString('utf-8');
      const secretBlock = `%%secret-start%%\n${plaintextText}\n%%secret-end%%`;
      result = result.replace(match[0], secretBlock);
    } catch (err) {
      console.error(`Warning: Failed to decrypt block: ${err.message}`);
    }
  }

  if (outputFile) {
    writeFileSync(outputFile, result, 'utf-8');
    console.error(`Decrypted: ${inputFile} -> ${outputFile}`);
  } else {
    process.stdout.write(result);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
