#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE_DIR="${REPO_ROOT}/deploy/customer-bundle"
PACKAGE_SCRIPT="${REPO_ROOT}/deploy/scripts/package-customer-bundle.sh"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

assert_file() {
  [ -f "$1" ] || fail "missing file: $1"
}

assert_executable() {
  [ -x "$1" ] || fail "file is not executable: $1"
}

assert_contains() {
  local file="$1"
  local expected="$2"
  grep -Fq "$expected" "$file" || fail "$file does not contain: $expected"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_mock_docker() {
  local dir="$1"
  cat > "${dir}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${MOCK_DOCKER_LOG}"
if [ "${1:-}" != "compose" ]; then
  echo "unexpected docker command: $*" >&2
  exit 1
fi
shift
case "${1:-}" in
  version|pull|down|up|logs)
    exit 0
    ;;
  exec)
    echo '{"status":"ok"}'
    exit 0
    ;;
  *)
    echo "unexpected docker compose command: $*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "${dir}/docker"
}

write_mock_openssl() {
  local dir="$1"
  cat > "${dir}/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "rand" ] && [ "${2:-}" = "-hex" ]; then
  count="${3:-16}"
  awk -v count="$count" 'BEGIN { for (i = 0; i < count * 2; i++) printf "a"; printf "\n" }'
  exit 0
fi
exec /usr/bin/openssl "$@"
EOF
  chmod +x "${dir}/openssl"
}

run_bundle_contract_test() {
  assert_file "${BUNDLE_DIR}/docker-compose.yml"
  assert_file "${BUNDLE_DIR}/.env.example"
  assert_file "${BUNDLE_DIR}/start.sh"
  assert_file "${BUNDLE_DIR}/upgrade.sh"
  assert_file "${PACKAGE_SCRIPT}"
  assert_executable "${BUNDLE_DIR}/start.sh"
  assert_executable "${BUNDLE_DIR}/upgrade.sh"
  assert_executable "${PACKAGE_SCRIPT}"

  assert_contains "${BUNDLE_DIR}/docker-compose.yml" 'image: ${CT_CVE_IMAGE'
  if grep -Fq "build:" "${BUNDLE_DIR}/docker-compose.yml"; then
    fail "customer compose file must not build from source"
  fi
  assert_contains "${BUNDLE_DIR}/start.sh" "database migrations run automatically"
}

run_package_test() {
  local tmpdir outdir extract image_ref version expected actual
  tmpdir="$(mktemp -d)"
  outdir="${tmpdir}/out"
  extract="${tmpdir}/extract"
  version="v9.9.9"
  image_ref="ghcr.io/carrtech-dev/ct-cve@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  "${PACKAGE_SCRIPT}" "$outdir" "$version" "$image_ref"

  assert_file "${outdir}/ct-cve-single-${version}.zip"
  assert_file "${outdir}/ct-cve-single-${version}.zip.sha256"
  assert_file "${outdir}/ct-cve-single.zip"
  assert_file "${outdir}/ct-cve-single.zip.sha256"

  expected="$(awk '{print $1; exit}' "${outdir}/ct-cve-single-${version}.zip.sha256")"
  actual="$(sha256_file "${outdir}/ct-cve-single-${version}.zip")"
  [ "$expected" = "$actual" ] || fail "versioned bundle checksum mismatch"

  mkdir -p "$extract"
  unzip -q "${outdir}/ct-cve-single-${version}.zip" -d "$extract"
  assert_file "${extract}/ct-cve/docker-compose.yml"
  assert_file "${extract}/ct-cve/.env.example"
  assert_file "${extract}/ct-cve/start.sh"
  assert_file "${extract}/ct-cve/upgrade.sh"
  assert_file "${extract}/ct-cve/VERSION"
  assert_executable "${extract}/ct-cve/start.sh"
  assert_executable "${extract}/ct-cve/upgrade.sh"
  assert_contains "${extract}/ct-cve/.env.example" "CT_CVE_IMAGE=${image_ref}"
  assert_contains "${extract}/ct-cve/VERSION" "$version"
}

run_start_bootstrap_test() {
  local tmpdir install mockbin output
  tmpdir="$(mktemp -d)"
  install="${tmpdir}/ct-cve"
  mockbin="${tmpdir}/bin"
  mkdir -p "$install" "$mockbin"
  cp "${BUNDLE_DIR}/docker-compose.yml" "${install}/docker-compose.yml"
  cp "${BUNDLE_DIR}/.env.example" "${install}/.env.example"
  cp "${BUNDLE_DIR}/start.sh" "${install}/start.sh"
  cp "${BUNDLE_DIR}/upgrade.sh" "${install}/upgrade.sh"
  chmod +x "${install}/start.sh" "${install}/upgrade.sh"
  write_mock_docker "$mockbin"
  write_mock_openssl "$mockbin"

  export MOCK_DOCKER_LOG="${tmpdir}/docker.log"
  output="$(
    cd "$install" &&
      PATH="${mockbin}:$PATH" ./start.sh
  )"

  assert_file "${install}/.env"
  assert_contains "${install}/.env" "POSTGRES_PASSWORD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  assert_contains "${install}/.env" "CT_CVE_DATABASE_URL=postgres://ct_cve:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@ct-cve-db:5432/ct_cve?sslmode=disable"
  assert_contains "${MOCK_DOCKER_LOG}" "compose pull ct-cve ct-cve-db"
  assert_contains "${MOCK_DOCKER_LOG}" "compose up -d"
  case "$output" in
    *"database migrations run automatically"*) ;;
    *) fail "start output does not explain automatic migrations" ;;
  esac
}

run_upgrade_from_zip_test() {
  local tmpdir outdir install mockbin version image_ref old_image_ref
  tmpdir="$(mktemp -d)"
  outdir="${tmpdir}/out"
  install="${tmpdir}/install"
  mockbin="${tmpdir}/bin"
  version="v9.9.9"
  image_ref="ghcr.io/carrtech-dev/ct-cve@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  old_image_ref="ghcr.io/carrtech-dev/ct-cve@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  "${PACKAGE_SCRIPT}" "$outdir" "$version" "$image_ref"
  mkdir -p "$install" "$mockbin"
  cp "${BUNDLE_DIR}/docker-compose.yml" "${install}/docker-compose.yml"
  cp "${BUNDLE_DIR}/.env.example" "${install}/.env.example"
  cp "${BUNDLE_DIR}/start.sh" "${install}/start.sh"
  cp "${BUNDLE_DIR}/upgrade.sh" "${install}/upgrade.sh"
  chmod +x "${install}/start.sh" "${install}/upgrade.sh"
  cat > "${install}/.env" <<EOF
CT_CVE_IMAGE=${old_image_ref}
CT_CVE_HTTP_PORT=8080
POSTGRES_PASSWORD=keep-this-password
CT_CVE_DATABASE_URL=postgres://ct_cve:keep-this-password@ct-cve-db:5432/ct_cve?sslmode=disable
CT_CVE_CT_OPS_CONNECTIONS=[]
EOF
  write_mock_docker "$mockbin"
  export MOCK_DOCKER_LOG="${tmpdir}/docker.log"

  (
    cd "$install" &&
      PATH="${mockbin}:$PATH" ./upgrade.sh --from-zip "${outdir}/ct-cve-single-${version}.zip" --no-start
  )

  assert_contains "${install}/.env" "POSTGRES_PASSWORD=keep-this-password"
  assert_contains "${install}/.env" "CT_CVE_IMAGE=${image_ref}"
  assert_contains "${install}/VERSION" "$version"
  compgen -G "${install}/ct-cve-install-backup-*.tar.gz" >/dev/null || fail "upgrade did not create a backup tarball"
  assert_contains "${MOCK_DOCKER_LOG}" "compose down --remove-orphans"
}

run_bundle_contract_test
run_package_test
run_start_bootstrap_test
run_upgrade_from_zip_test

echo "customer bundle tests passed"
