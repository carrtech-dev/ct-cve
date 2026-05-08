#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CT-CVE customer start script
#
# Runs the single-host CT-CVE stack from a release bundle. The service applies
# embedded database migrations during startup before /healthz becomes available.
#
# Usage:
#   ./start.sh             Start or update CT-CVE
#   ./start.sh --logs      Tail container logs
#   ./start.sh --down      Stop CT-CVE while preserving database volume data
#   ./start.sh --version   Show bundle and image version details
#   ./start.sh --help      Show this help
#   ./upgrade.sh           Back up this install and upgrade to a newer release
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOCS_URL="https://github.com/carrtech-dev/ct-cve"
SUPPORT_URL="https://github.com/carrtech-dev/ct-cve/issues"
REQUIRED_FILES=(docker-compose.yml .env.example start.sh upgrade.sh)

show_help() {
  cat <<EOF
CT-CVE single-host installer

Commands:
  ./start.sh             Start or update CT-CVE
  ./start.sh --logs      Tail logs from all containers (Ctrl-C to stop)
  ./start.sh --down      Stop the stack (named volumes are preserved)
  ./start.sh --version   Show bundle and image details
  ./start.sh --help      Show this message
  ./upgrade.sh           Back up this install and upgrade to a newer release

Documentation: ${DOCS_URL}
Support:       ${SUPPORT_URL}
EOF
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
  export "${key}=${value}"
}

env_example_value() {
  local key="$1"
  sed -n "s/^${key}=//p" .env.example | head -n1
}

require_openssl() {
  local purpose="$1"
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: 'openssl' is required to ${purpose}." >&2
    exit 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: 'docker' is not installed or not on PATH." >&2
    echo "Install Docker Engine 24+ with the Compose plugin: https://docs.docker.com/engine/install/" >&2
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' plugin not found." >&2
    echo "Upgrade Docker Engine to a release that bundles the Compose plugin." >&2
    exit 1
  fi
}

check_bundle_files() {
  local missing=()
  local file

  for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
      missing+=("$file")
    fi
  done

  if [ ${#missing[@]} -eq 0 ]; then
    return 0
  fi

  echo "ERROR: this CT-CVE bundle is incomplete or corrupt." >&2
  echo "Missing required files:" >&2
  for file in "${missing[@]}"; do echo "  - $file" >&2; done
  echo "" >&2
  echo "Re-download the release bundle and unpack it into a clean directory." >&2
  exit 1
}

load_env() {
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
}

check_env() {
  if [ ! -f ".env" ]; then
    cp .env.example .env
    chmod 600 .env
    echo "Created .env from .env.example."
  fi

  load_env

  if [ -z "${CT_CVE_IMAGE:-}" ]; then
    upsert_env_var "CT_CVE_IMAGE" "$(env_example_value CT_CVE_IMAGE)"
  fi
  if [ -z "${CT_CVE_HTTP_PORT:-}" ]; then
    upsert_env_var "CT_CVE_HTTP_PORT" "8080"
  fi
  if [ -z "${POSTGRES_PASSWORD:-}" ]; then
    require_openssl "generate POSTGRES_PASSWORD on first run"
    upsert_env_var "POSTGRES_PASSWORD" "$(openssl rand -hex 16)"
    echo "Generated POSTGRES_PASSWORD and wrote it to .env."
  fi
  if [ -z "${CT_CVE_DATABASE_URL:-}" ]; then
    upsert_env_var "CT_CVE_DATABASE_URL" "postgres://ct_cve:${POSTGRES_PASSWORD}@ct-cve-db:5432/ct_cve?sslmode=disable"
    echo "Set CT_CVE_DATABASE_URL for the bundled database."
  fi
  if [ -z "${CT_CVE_CT_OPS_CONNECTIONS:-}" ]; then
    upsert_env_var "CT_CVE_CT_OPS_CONNECTIONS" "[]"
  fi
}

show_version() {
  if [ -f "VERSION" ]; then
    echo "Bundle version: $(cat VERSION)"
  else
    echo "Bundle version: unknown (no VERSION file in $(pwd))"
  fi

  if [ -f ".env" ]; then
    load_env
    echo "Image:          ${CT_CVE_IMAGE:-unknown}"
  else
    echo "Image:          $(env_example_value CT_CVE_IMAGE)"
  fi
}

wait_for_health() {
  local deadline=$((SECONDS + 120))

  echo "Waiting for CT-CVE health check; database migrations run automatically during startup..."
  while [ "$SECONDS" -lt "$deadline" ]; do
    if docker compose exec -T ct-cve wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  echo "" >&2
  echo "ERROR: CT-CVE did not become healthy after startup." >&2
  echo "Recent logs:" >&2
  docker compose logs --tail 80 ct-cve ct-cve-db || true
  exit 1
}

start_stack() {
  check_bundle_files
  require_docker
  check_env

  echo "Pulling CT-CVE images from GHCR..."
  if ! docker compose pull ct-cve ct-cve-db; then
    echo "" >&2
    echo "ERROR: failed to pull CT-CVE images." >&2
    echo "Check network access to ghcr.io, or verify CT_CVE_IMAGE in .env." >&2
    exit 1
  fi

  docker compose down --remove-orphans >/dev/null 2>&1 || true

  echo "Starting CT-CVE..."
  if ! docker compose up -d; then
    echo "" >&2
    echo "ERROR: 'docker compose up' failed." >&2
    echo "Recent logs:" >&2
    docker compose logs --tail 80 || true
    exit 1
  fi

  wait_for_health

  echo ""
  echo "CT-CVE is running at http://localhost:${CT_CVE_HTTP_PORT:-8080}/status"
  echo "Tail logs with: ./start.sh --logs"
  echo "Stop with:      ./start.sh --down"
}

stop_stack() {
  require_docker
  echo "Stopping CT-CVE..."
  docker compose down
  echo "Stopped. Database volume data is preserved."
}

tail_logs() {
  require_docker
  exec docker compose logs -f --tail 100
}

if [ "$#" -eq 0 ]; then
  start_stack
  exit 0
fi

if [ "$#" -gt 1 ]; then
  echo "ERROR: only one option may be passed at a time." >&2
  show_help >&2
  exit 1
fi

case "$1" in
  --logs)          tail_logs ;;
  --down)          stop_stack ;;
  --version|-v)    show_version ;;
  --help|-h)       show_help ;;
  *)
    echo "ERROR: unknown option '$1'" >&2
    echo "" >&2
    show_help >&2
    exit 1
    ;;
esac
