#!/usr/bin/env bash
#
# Git pre-commit hook: prevents committing plaintext in secret blocks.
#
# Checks that no staged .md files contain %%secret-start%% markers.
# If the plugin is working correctly, all secret blocks should be encrypted
# to ````ocke-v1 before reaching disk. If %%secret-start%% is found in a
# staged file, it means plaintext would be committed to Git.
#
# Install:
#   cp tools/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or with a symlink:
#   ln -sf ../../tools/pre-commit-hook.sh .git/hooks/pre-commit

set -euo pipefail

RED='\033[0;31m'
NC='\033[0m' # No Color

# Get list of staged .md files
STAGED_MD_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.md$' || true)

if [ -z "$STAGED_MD_FILES" ]; then
  exit 0
fi

FOUND_PLAINTEXT=0

for file in $STAGED_MD_FILES; do
  # Check staged content (not working tree) for secret markers
  if git show ":$file" 2>/dev/null | grep -q '%%secret-start%%'; then
    echo -e "${RED}ERROR: Plaintext secret block found in staged file: $file${NC}"
    echo "  The file contains %%secret-start%% markers which means"
    echo "  the encryption plugin did not encrypt before save."
    echo ""
    echo "  Possible causes:"
    echo "    - Plugin was disabled or not loaded"
    echo "    - KMS credentials were unavailable"
    echo "    - File was edited outside Obsidian"
    echo ""
    echo "  Fix: Open the file in Obsidian with the plugin enabled,"
    echo "  save it, then stage again."
    echo ""
    FOUND_PLAINTEXT=1
  fi
done

if [ $FOUND_PLAINTEXT -ne 0 ]; then
  echo -e "${RED}Commit blocked: plaintext secrets detected.${NC}"
  echo "Use 'git commit --no-verify' to bypass (NOT recommended)."
  exit 1
fi

exit 0
