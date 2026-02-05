#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCES_FILE="$ROOT/docs/DESIGN_PDF_SOURCES.md"
OUTPUT="$ROOT/eBPF Runtime Security Agent Design.pdf"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "pandoc not found. Install pandoc before generating the PDF." >&2
  exit 1
fi
if ! command -v tectonic >/dev/null 2>&1; then
  echo "tectonic not found. Install tectonic before generating the PDF." >&2
  exit 1
fi
if [[ ! -f "$SOURCES_FILE" ]]; then
  echo "Missing source list: $SOURCES_FILE" >&2
  exit 1
fi

DATE_UTC="$(date -u +"%Y-%m-%d")"
GIT_SHA="$(git -C "$ROOT" rev-parse --short HEAD)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

cat >"$tmp" <<EOF
---
title: "eBPF Runtime Security Agent Design"
date: "$DATE_UTC"
git_sha: "$GIT_SHA"
note: "Markdown docs in docs/ are the source of truth."
---
EOF

while IFS= read -r line; do
  if [[ "$line" =~ ^[0-9]+[.] ]]; then
    path="${line#*. }"
    file="$ROOT/$path"
    if [[ ! -f "$file" ]]; then
      echo "Missing source: $file" >&2
      exit 1
    fi
    printf "\n\\\\newpage\n" >>"$tmp"
    cat "$file" >>"$tmp"
  fi
done <"$SOURCES_FILE"

pandoc "$tmp" \
  --pdf-engine=tectonic \
  --toc \
  -o "$OUTPUT"

echo "Generated PDF: $OUTPUT"
