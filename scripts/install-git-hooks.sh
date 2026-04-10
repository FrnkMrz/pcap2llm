#!/usr/bin/env bash
# install-git-hooks.sh — install project Git hooks into .git/hooks/
#
# Run once after cloning:
#   bash scripts/install-git-hooks.sh
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_SRC="$REPO_ROOT/scripts/git-hooks"
HOOKS_DST="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_SRC" ]; then
  echo "Error: hook sources not found at $HOOKS_SRC" >&2
  exit 1
fi

for hook in "$HOOKS_SRC"/*; do
  name="$(basename "$hook")"
  dest="$HOOKS_DST/$name"
  cp "$hook" "$dest"
  chmod +x "$dest"
  echo "Installed: .git/hooks/$name"
done

echo ""
echo "Git hooks installed successfully."
echo "The pre-commit hook will block accidental commits of .local/ contents."
