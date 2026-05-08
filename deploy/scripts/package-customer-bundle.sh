#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <output-dir> <version> <ct-cve-image-ref>" >&2
  exit 1
fi

OUT_DIR="$1"
VERSION="$2"
IMAGE_REF="$3"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/deploy/customer-bundle"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found in PATH." >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_checksum() {
  local file="$1"
  local hash
  hash="$(sha256_file "$file")"
  printf '%s  %s\n' "$hash" "$(basename "$file")" > "${file}.sha256"
}

need zip

if [ -z "$VERSION" ] || [ -z "$IMAGE_REF" ]; then
  echo "ERROR: version and image reference are required." >&2
  exit 1
fi

case "$VERSION" in
  v*) ;;
  *) VERSION="v${VERSION}" ;;
esac

for file in docker-compose.yml .env.example start.sh upgrade.sh; do
  if [ ! -f "${SOURCE_DIR}/${file}" ]; then
    echo "ERROR: missing customer bundle source file: ${file}" >&2
    exit 1
  fi
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STAGE_DIR="$(mktemp -d -t ct-cve-bundle.XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT

BUNDLE_DIR="${STAGE_DIR}/ct-cve"
mkdir -p "$BUNDLE_DIR"

cp "${SOURCE_DIR}/docker-compose.yml" "${BUNDLE_DIR}/docker-compose.yml"
awk -v image_ref="$IMAGE_REF" '
  BEGIN { replaced = 0 }
  /^CT_CVE_IMAGE=/ {
    print "CT_CVE_IMAGE=" image_ref
    replaced = 1
    next
  }
  { print }
  END {
    if (!replaced) {
      print "CT_CVE_IMAGE=" image_ref
    }
  }
' "${SOURCE_DIR}/.env.example" > "${BUNDLE_DIR}/.env.example"
cp "${SOURCE_DIR}/start.sh" "${BUNDLE_DIR}/start.sh"
cp "${SOURCE_DIR}/upgrade.sh" "${BUNDLE_DIR}/upgrade.sh"
if [ -f "${SOURCE_DIR}/README.md" ]; then
  cp "${SOURCE_DIR}/README.md" "${BUNDLE_DIR}/README.md"
fi
printf '%s\n' "$VERSION" > "${BUNDLE_DIR}/VERSION"
chmod +x "${BUNDLE_DIR}/start.sh" "${BUNDLE_DIR}/upgrade.sh"

VERSIONED_ZIP="${OUT_DIR}/ct-cve-single-${VERSION}.zip"
STABLE_ZIP="${OUT_DIR}/ct-cve-single.zip"
rm -f "$VERSIONED_ZIP" "${VERSIONED_ZIP}.sha256" "$STABLE_ZIP" "${STABLE_ZIP}.sha256"

(cd "$STAGE_DIR" && zip -qr "$VERSIONED_ZIP" ct-cve)
cp "$VERSIONED_ZIP" "$STABLE_ZIP"
write_checksum "$VERSIONED_ZIP"
write_checksum "$STABLE_ZIP"

echo "Wrote ${VERSIONED_ZIP}"
