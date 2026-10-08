#!/usr/bin/env bash
# render the svg glyphs into the white masks the app tints at runtime
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RSVG="${BYE_RSVG:-rsvg-convert}"
command -v "${RSVG}" >/dev/null || { echo "rsvg-convert not found, set BYE_RSVG" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# material symbols have bare paths, which take their fill here; the others are drawn white already
for svg in "${ROOT}"/art/icons/material/*.svg; do
    name="$(basename "${svg}" .svg)"
    sed 's/<path /<path fill="#ffffff" /g' "${svg}" > "${TMP}/${name}.svg"
    "${RSVG}" -w 96 -h 96 "${TMP}/${name}.svg" -o "${ROOT}/app/icons/ic-${name}.png"
done
for svg in "${ROOT}"/art/icons/own/*.svg; do
    name="$(basename "${svg}" .svg)"
    "${RSVG}" -w 96 -h 96 "${svg}" -o "${ROOT}/app/icons/ic-${name}.png"
done
echo "rendered $(ls "${ROOT}"/art/icons/material/*.svg "${ROOT}"/art/icons/own/*.svg | wc -l) glyphs"
