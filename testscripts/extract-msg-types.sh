#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"

# For each .proto, read its package and Msg* messages and print /package.MsgName
while IFS= read -r -d '' f; do
  # Extract package name
  pkg="$(awk '/^package/{gsub(/;/,""); print $2; exit}' "$f")"
  [[ -z "$pkg" ]] && continue
  
  # Find Msg* messages and print them
  awk -v P="$pkg" '/^message Msg/{print "/" P "." $2}' "$f"
done < <(find "$ROOT" -type f -name '*.proto' -print0) | sort -u
