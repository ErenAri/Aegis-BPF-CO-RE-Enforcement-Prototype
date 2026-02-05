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
MONO_FONT=""
MAIN_FONT=""

if command -v fc-list >/dev/null 2>&1; then
  if fc-list | grep -qi "DejaVu Sans Mono"; then
    MONO_FONT="DejaVu Sans Mono"
  elif fc-list | grep -qi "Noto Sans Mono"; then
    MONO_FONT="Noto Sans Mono"
  fi
  if fc-list | grep -qi "DejaVu Serif"; then
    MAIN_FONT="DejaVu Serif"
  elif fc-list | grep -qi "Noto Serif"; then
    MAIN_FONT="Noto Serif"
  fi
fi

tmp="$(mktemp --suffix .md)"
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

args=()
if [[ -n "$MONO_FONT" ]]; then
  args+=("-V" "monofont=$MONO_FONT")
fi
if [[ -n "$MAIN_FONT" ]]; then
  args+=("-V" "mainfont=$MAIN_FONT")
fi

pandoc "$tmp" \
  --from=markdown \
  --pdf-engine=tectonic \
  --toc \
  "${args[@]}" \
  -o "$OUTPUT"

echo "Generated PDF: $OUTPUT"
