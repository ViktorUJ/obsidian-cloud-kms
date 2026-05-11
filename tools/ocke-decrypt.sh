#!/usr/bin/env bash
#
# ocke-decrypt.sh — Decrypt OCKE encrypted blocks/files using AWS CLI + Python
#
# Usage:
#   ./ocke-decrypt.sh <file>              # Decrypt and print to stdout
#   ./ocke-decrypt.sh <file> -o <output>  # Decrypt and write to file
#
# Requirements:
#   - aws cli (configured with credentials that have kms:Decrypt)
#   - python3 (for AES-256-GCM decryption and binary parsing)
#
# This script works WITHOUT Node.js or Obsidian.
# Useful for: disaster recovery, CI/CD pipelines, backup verification.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <file> [-o output_file] [--vault-name NAME] [--file-path PATH]"
  echo ""
  echo "Decrypts OCKE encrypted content (markdown blocks or binary files)."
  echo ""
  echo "Options:"
  echo "  -o <file>           Write output to file (default: stdout)"
  echo "  --vault-name NAME   Obsidian vault name (folder name)"
  echo "  --file-path PATH    Vault-relative file path used during encryption"
  echo ""
  echo "Environment (alternative to flags):"
  echo "  OCKE_VAULT_NAME     Vault name for encryption context"
  echo "  OCKE_FILE_PATH      File path for encryption context"
  echo ""
  echo "Requires: aws cli, python3, pip install cryptography"
  exit 1
fi

INPUT_FILE="$1"
shift

OUTPUT_FILE=""
VAULT_NAME="${OCKE_VAULT_NAME:-}"
FILE_PATH="${OCKE_FILE_PATH:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTPUT_FILE="$2"; shift 2 ;;
    --vault-name) VAULT_NAME="$2"; shift 2 ;;
    --file-path) FILE_PATH="$2"; shift 2 ;;
    *) shift ;;
  esac
done

export OCKE_VAULT_NAME="$VAULT_NAME"
export OCKE_FILE_PATH="$FILE_PATH"

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: File not found: $INPUT_FILE" >&2
  exit 1
fi

python3 - "$INPUT_FILE" "$OUTPUT_FILE" << 'PYTHON_SCRIPT'
import sys
import os
import struct
import base64
import json
import subprocess
import re
from pathlib import Path

def aws_kms_decrypt(ciphertext_blob, encryption_context, region):
    """Call aws kms decrypt and return plaintext bytes."""
    import tempfile
    
    # Write ciphertext to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(ciphertext_blob)
        tmp_path = f.name
    
    try:
        ctx_str = ','.join(f'{k}={v}' for k, v in encryption_context.items())
        cmd = [
            'aws', 'kms', 'decrypt',
            '--ciphertext-blob', f'fileb://{tmp_path}',
            '--encryption-context', ctx_str,
            '--region', region,
            '--output', 'json'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        response = json.loads(result.stdout)
        plaintext_b64 = response['Plaintext']
        return base64.b64decode(plaintext_b64)
    finally:
        os.unlink(tmp_path)

def aes_gcm_decrypt(key, nonce, ciphertext, auth_tag):
    """Decrypt AES-256-GCM using Python cryptography or PyCryptodome."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        # GCM expects ciphertext + tag concatenated
        ct_with_tag = ciphertext + auth_tag
        return aesgcm.decrypt(nonce, ct_with_tag, None)
    except ImportError:
        pass
    
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ImportError:
        pass
    
    print("Error: Install 'cryptography' or 'pycryptodome':", file=sys.stderr)
    print("  pip install cryptography", file=sys.stderr)
    print("  # or", file=sys.stderr)
    print("  pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

def parse_ocke_binary(data):
    """Parse OCKE binary format and return fields."""
    offset = 0
    
    # Magic (4 bytes)
    magic = data[offset:offset+4]
    if magic != b'OCKE':
        return None
    offset += 4
    
    # Version (uint16 BE)
    version = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # ProviderIdLen (1 byte) + ProviderId
    provider_id_len = data[offset]
    offset += 1
    provider_id = data[offset:offset+provider_id_len].decode('ascii')
    offset += provider_id_len
    
    # CmkIdLen (uint16 BE) + CmkId
    cmk_id_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    cmk_id = data[offset:offset+cmk_id_len].decode('utf-8')
    offset += cmk_id_len
    
    # WrappedDekLen (uint16 BE) + WrappedDek
    wrapped_dek_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    wrapped_dek = data[offset:offset+wrapped_dek_len]
    offset += wrapped_dek_len
    
    # Nonce (12 bytes)
    nonce = data[offset:offset+12]
    offset += 12
    
    # AuthTag (16 bytes)
    auth_tag = data[offset:offset+16]
    offset += 16
    
    # CiphertextLen (uint32 BE) + Ciphertext
    ciphertext_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    ciphertext = data[offset:offset+ciphertext_len]
    
    return {
        'version': version,
        'provider_id': provider_id,
        'cmk_id': cmk_id,
        'wrapped_dek': wrapped_dek,
        'nonce': nonce,
        'auth_tag': auth_tag,
        'ciphertext': ciphertext,
    }

def extract_region_from_arn(arn):
    """Extract AWS region from KMS key ARN."""
    parts = arn.split(':')
    if len(parts) >= 6 and parts[0] == 'arn' and parts[2] == 'kms':
        return parts[3]
    return 'us-east-1'

def decrypt_record(record, file_path='', vault_name=''):
    """Decrypt a single OCKE record."""
    region = extract_region_from_arn(record['cmk_id'])
    
    encryption_context = {
        'vaultName': vault_name,
        'filePath': file_path,
        'formatVersion': str(record['version']),
    }
    
    # Unwrap DEK via KMS
    dek = aws_kms_decrypt(record['wrapped_dek'], encryption_context, region)
    
    # Decrypt content via AES-256-GCM
    plaintext = aes_gcm_decrypt(dek, record['nonce'], record['ciphertext'], record['auth_tag'])
    
    return plaintext

def main():
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    
    file_path = Path(input_file).name
    vault_name = ''  # Can be set via env var if needed
    
    if os.environ.get('OCKE_VAULT_NAME'):
        vault_name = os.environ['OCKE_VAULT_NAME']
    
    with open(input_file, 'rb') as f:
        raw_data = f.read()
    
    # Check if it's a binary OCKE file (starts with magic bytes)
    if raw_data[:4] == b'OCKE':
        record = parse_ocke_binary(raw_data)
        if not record:
            print("Error: Failed to parse OCKE binary format", file=sys.stderr)
            sys.exit(1)
        
        plaintext = decrypt_record(record, file_path, vault_name)
        
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            print(f"Decrypted: {input_file} -> {output_file}")
        else:
            sys.stdout.buffer.write(plaintext)
        return
    
    # It's a text file — look for ````ocke-v1 blocks
    text = raw_data.decode('utf-8')
    pattern = re.compile(r'````ocke-v1\n([\s\S]*?)\n````')
    
    matches = list(pattern.finditer(text))
    if not matches:
        print("No encrypted blocks found in file", file=sys.stderr)
        sys.exit(1)
    
    result = text
    for match in matches:
        b64_content = match.group(1).strip().replace('\n', '').replace('\r', '').replace(' ', '')
        binary_data = base64.b64decode(b64_content)
        record = parse_ocke_binary(binary_data)
        
        if not record:
            continue
        
        plaintext = decrypt_record(record, file_path, vault_name)
        plaintext_text = plaintext.decode('utf-8')
        
        secret_block = f'%%secret-start%%\n{plaintext_text}\n%%secret-end%%'
        result = result.replace(match.group(0), secret_block)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Decrypted: {input_file} -> {output_file}")
    else:
        print(result)

if __name__ == '__main__':
    main()
PYTHON_SCRIPT
