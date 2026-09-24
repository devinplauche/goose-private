#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# A fresh fork may not have any releases yet; skip instead of failing the
# docs deployment.
acp_ref=$(gh api 'repos/{owner}/{repo}/releases/latest' --jq '.tag_name' 2>/dev/null || true)
if [ -z "$acp_ref" ]; then
  echo "No releases published yet; skipping released ACP reference generation."
  exit 0
fi
echo "Using goose release $acp_ref for ACP documentation."

if ! git rev-parse --verify --quiet "refs/tags/$acp_ref" >/dev/null; then
  echo "Release tag $acp_ref is not available locally. Run 'git fetch --tags'." >&2
  exit 1
fi

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT

schema="$temp_dir/acp-schema.json"
meta="$temp_dir/acp-meta.json"

git show "$acp_ref:crates/goose/acp-schema.json" > "$schema"
git show "$acp_ref:crates/goose/acp-meta.json" > "$meta"
node documentation/scripts/generate-acp-docs.js "$schema" "$meta" \
  documentation/docs/gdk/acp/reference.md "$acp_ref"

