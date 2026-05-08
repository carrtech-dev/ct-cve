#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CT-CVE customer upgrade script
#
# Run from inside an existing CT-CVE release bundle. The script backs up local
# install files, stops the stack without deleting named volumes, installs newer
# bundle files in place, preserves .env, and optionally starts the upgraded
# stack. The upgraded service applies database migrations on startup.
# =============================================================================

REPO_OWNER="carrtech-dev"
REPO_NAME="ct-cve"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FROM_ZIP=""
START_AFTER_UPGRADE=true
VERSION_OVERRIDE="${CT_CVE_VERSION:-}"
DOCKER_CMD=(docker)

show_help() {
  cat <<EOF
CT-CVE upgrade helper

Usage:
  ./upgrade.sh
  ./upgrade.sh --version v0.6.0
  ./upgrade.sh --from-zip /path/to/ct-cve-single-v0.6.0.zip
  ./upgrade.sh --no-start

By default, the latest release bundle is downloaded from GitHub. A local
configuration backup is written before any files are replaced. Database data is
kept in Docker named volumes and migrations run automatically on next startup.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from-zip)
      FROM_ZIP="${2:-}"
      if [ -z "$FROM_ZIP" ]; then
        echo "ERROR: --from-zip requires a path." >&2
        exit 1
      fi
      shift 2
      ;;
    --version)
      VERSION_OVERRIDE="${2:-}"
      if [ -z "$VERSION_OVERRIDE" ]; then
        echo "ERROR: --version requires a version, for example v0.6.0." >&2
        exit 1
      fi
      shift 2
      ;;
    --no-start)
      START_AFTER_UPGRADE=false
      shift
      ;;
    --help|-h)
      show_help
      exit 0
      ;;
    *)
      echo "ERROR: unknown option '$1'." >&2
      echo "" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found in PATH." >&2
    exit 1
  fi
}

require_existing_bundle() {
  local missing=()
  local file

  for file in docker-compose.yml start.sh .env; do
    if [ ! -f "$file" ]; then
      missing+=("$file")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: this does not look like an existing CT-CVE install." >&2
    echo "Missing required files:" >&2
    for file in "${missing[@]}"; do echo "  - $file" >&2; done
    echo "Run upgrade.sh from inside the existing ct-cve directory." >&2
    exit 1
  fi
}

require_docker() {
  need docker

  if docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return 0
  fi

  if command -v sudo >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
    echo "Docker requires elevated privileges on this host; using sudo for Docker commands."
    return 0
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' plugin not found." >&2
    exit 1
  fi

  echo "ERROR: Docker is installed, but this user cannot access the Docker daemon." >&2
  echo "Run this script as a user with Docker access, or run it with sudo." >&2
  echo "Original Docker error:" >&2
  docker info >/dev/null
}

normalize_tag() {
  local value="$1"

  case "$value" in
    ct-cve-v*) printf '%s\n' "$value" ;;
    v*) printf 'ct-cve-%s\n' "$value" ;;
    *) printf 'ct-cve-v%s\n' "$value" ;;
  esac
}

latest_release_tag() {
  local tmp tag
  tmp="$(mktemp -t ct-cve.XXXXXX.release.json)"
  TEMP_FILES+=("$tmp")

  if ! curl -fsSL -o "$tmp" "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"; then
    echo "ERROR: could not read latest CT-CVE release from GitHub." >&2
    exit 1
  fi

  tag="$(awk -F '"' '/"tag_name":[[:space:]]*"/ { print $4; exit }' "$tmp")"
  if [ -z "$tag" ]; then
    echo "ERROR: latest CT-CVE release response did not include a tag_name." >&2
    exit 1
  fi

  printf '%s\n' "$tag"
}

sha256_file() {
  openssl dgst -sha256 "$1" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]'
}

download_bundle() {
  need curl
  need openssl

  local tag version url checksum_url checksum_tmp expected actual
  if [ -n "$VERSION_OVERRIDE" ]; then
    tag="$(normalize_tag "$VERSION_OVERRIDE")"
    version="${tag#ct-cve-}"
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/ct-cve-single-${version}.zip"
  else
    tag="$(latest_release_tag)"
    version="${tag#ct-cve-}"
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/ct-cve-single.zip"
  fi
  checksum_url="${url}.sha256"

  BUNDLE_ZIP="$(mktemp -t ct-cve.XXXXXX.zip)"
  checksum_tmp="$(mktemp -t ct-cve.XXXXXX.sha256)"
  TEMP_FILES+=("$BUNDLE_ZIP" "$checksum_tmp")

  echo "Downloading CT-CVE ${version}..."
  curl -fsSL -o "$BUNDLE_ZIP" "$url"
  curl -fsSL -o "$checksum_tmp" "$checksum_url"

  expected="$(awk 'NF { print $1; exit }' "$checksum_tmp" | tr '[:upper:]' '[:lower:]')"
  actual="$(sha256_file "$BUNDLE_ZIP")"
  if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    echo "ERROR: bundle checksum mismatch." >&2
    echo "Expected: ${expected:-<empty>}" >&2
    echo "Actual:   $actual" >&2
    exit 1
  fi
}

verify_local_bundle_checksum() {
  local checksum_file expected actual
  checksum_file="${FROM_ZIP}.sha256"
  if [ ! -f "$checksum_file" ]; then
    return 0
  fi

  need openssl
  expected="$(awk 'NF { print $1; exit }' "$checksum_file" | tr '[:upper:]' '[:lower:]')"
  actual="$(sha256_file "$FROM_ZIP")"
  if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    echo "ERROR: local bundle checksum mismatch for $FROM_ZIP." >&2
    echo "Expected: ${expected:-<empty>}" >&2
    echo "Actual:   $actual" >&2
    exit 1
  fi
}

make_backup() {
  local timestamp files=() file
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP_FILE="ct-cve-install-backup-${timestamp}.tar.gz"

  for file in docker-compose.yml .env .env.example start.sh upgrade.sh VERSION README.md; do
    if [ -e "$file" ]; then
      files+=("$file")
    fi
  done

  echo "Backing up current install files..."
  tar -czf "$BACKUP_FILE" "${files[@]}"
  echo "  $BACKUP_FILE"
}

unpack_new_bundle() {
  need unzip

  UNPACK_DIR="$(mktemp -d -t ct-cve-upgrade.XXXXXX)"
  TEMP_DIRS+=("$UNPACK_DIR")

  unzip -q "$BUNDLE_ZIP" -d "$UNPACK_DIR"
  NEW_BUNDLE_DIR="$UNPACK_DIR/ct-cve"
  if [ ! -f "$NEW_BUNDLE_DIR/docker-compose.yml" ] \
    || [ ! -f "$NEW_BUNDLE_DIR/.env.example" ] \
    || [ ! -f "$NEW_BUNDLE_DIR/start.sh" ] \
    || [ ! -f "$NEW_BUNDLE_DIR/upgrade.sh" ]; then
    echo "ERROR: upgrade bundle is missing docker-compose.yml, .env.example, start.sh, or upgrade.sh." >&2
    exit 1
  fi
}

stop_stack() {
  echo "Stopping CT-CVE stack; named volumes are preserved..."
  "${DOCKER_CMD[@]}" compose down --remove-orphans >/dev/null 2>&1 || true
}

upsert_env_var() {
  local key="$1"
  local value="$2"

  awk -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    $0 ~ "^#?[[:space:]]*" key "=" {
      print key "=" value
      replaced = 1
      next
    }
    { print }
    END {
      if (!replaced) {
        print key "=" value
      }
    }
  ' .env > .env.tmp && mv .env.tmp .env

  chmod 600 .env
}

refresh_release_image_env_ref() {
  local new_value current_value
  new_value="$(sed -n 's/^CT_CVE_IMAGE=//p' .env.example | head -n1)"
  if [ -z "$new_value" ]; then
    return 0
  fi

  current_value="$(sed -n 's/^CT_CVE_IMAGE=//p' .env | head -n1)"
  if [ -z "$current_value" ]; then
    upsert_env_var "CT_CVE_IMAGE" "$new_value"
    return 0
  fi

  case "$current_value" in
    ghcr.io/carrtech-dev/ct-cve:*|ghcr.io/carrtech-dev/ct-cve@sha256:*)
      upsert_env_var "CT_CVE_IMAGE" "$new_value"
      ;;
    *)
      echo "WARN: preserving custom CT_CVE_IMAGE override in .env." >&2
      echo "      Ensure your custom image includes this CT-CVE release." >&2
      ;;
  esac
}

install_new_bundle_files() {
  echo "Installing new release files..."

  cp "$NEW_BUNDLE_DIR/docker-compose.yml" docker-compose.yml
  cp "$NEW_BUNDLE_DIR/.env.example" .env.example
  cp "$NEW_BUNDLE_DIR/start.sh" start.sh
  cp "$NEW_BUNDLE_DIR/upgrade.sh" upgrade.sh
  if [ -f "$NEW_BUNDLE_DIR/README.md" ]; then
    cp "$NEW_BUNDLE_DIR/README.md" README.md
  fi
  if [ -f "$NEW_BUNDLE_DIR/VERSION" ]; then
    cp "$NEW_BUNDLE_DIR/VERSION" VERSION
  fi

  chmod +x start.sh upgrade.sh
  refresh_release_image_env_ref
}

start_stack() {
  if ! $START_AFTER_UPGRADE; then
    echo "Upgrade files installed. Start CT-CVE with ./start.sh when ready."
    return 0
  fi

  echo "Starting upgraded CT-CVE stack..."
  ./start.sh
}

cleanup() {
  local file dir
  for file in "${TEMP_FILES[@]:-}"; do
    rm -f "$file"
  done
  for dir in "${TEMP_DIRS[@]:-}"; do
    rm -rf "$dir"
  done
}

TEMP_FILES=()
TEMP_DIRS=()
BUNDLE_ZIP=""
BACKUP_FILE=""
UNPACK_DIR=""
NEW_BUNDLE_DIR=""
trap cleanup EXIT

require_existing_bundle
require_docker

if [ -n "$FROM_ZIP" ]; then
  if [ ! -f "$FROM_ZIP" ]; then
    echo "ERROR: local bundle not found: $FROM_ZIP" >&2
    exit 1
  fi
  verify_local_bundle_checksum
  BUNDLE_ZIP="$FROM_ZIP"
else
  download_bundle
fi

unpack_new_bundle
make_backup
stop_stack
install_new_bundle_files
start_stack

echo ""
echo "Upgrade complete."
echo "Backup: $BACKUP_FILE"
