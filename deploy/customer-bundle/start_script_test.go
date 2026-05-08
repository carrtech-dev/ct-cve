package customerbundle_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartScriptFallsBackToSudoDockerWhenDaemonAccessIsDenied(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyFile(t, "start.sh", filepath.Join(dir, "start.sh"))
	writeFile(t, filepath.Join(dir, "docker-compose.yml"), "services: {}\n")
	writeFile(t, filepath.Join(dir, ".env.example"), "CT_CVE_IMAGE=ghcr.io/carrtech-dev/ct-cve:latest\n")
	writeFile(t, filepath.Join(dir, "upgrade.sh"), "#!/usr/bin/env bash\n")
	writeFile(t, filepath.Join(dir, ".env"), strings.Join([]string{
		"CT_CVE_IMAGE=ghcr.io/carrtech-dev/ct-cve:latest",
		"CT_CVE_HTTP_PORT=8080",
		"POSTGRES_PASSWORD=test-password",
		"CT_CVE_DATABASE_URL=postgres://ct_cve:test-password@ct-cve-db:5432/ct_cve?sslmode=disable",
		"CT_CVE_CT_OPS_CONNECTIONS=[]",
		"",
	}, "\n"))

	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatalf("Mkdir bin: %v", err)
	}
	writeExecutable(t, filepath.Join(binDir, "docker"), `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "compose" ] && [ "${2:-}" = "version" ]; then
  exit 0
fi
if [ "${1:-}" = "info" ]; then
  if [ "${CT_TEST_SUDO_DOCKER:-}" = "1" ]; then
    exit 0
  fi
  echo "permission denied while trying to connect to the docker API" >&2
  exit 1
fi
if [ "${1:-}" = "compose" ]; then
  case "${2:-}" in
    pull|down|up|exec|logs) exit 0 ;;
  esac
fi
echo "unexpected docker args: $*" >&2
exit 1
`)
	writeExecutable(t, filepath.Join(binDir, "sudo"), `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "docker" ]; then
  echo "unexpected sudo args: $*" >&2
  exit 1
fi
shift
CT_TEST_SUDO_DOCKER=1 docker "$@"
`)

	cmd := exec.Command("bash", "./start.sh")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("start.sh failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "using sudo for Docker commands") {
		t.Fatalf("start.sh did not report sudo Docker fallback:\n%s", output)
	}
	if !strings.Contains(string(output), "CT-CVE is running") {
		t.Fatalf("start.sh did not complete startup:\n%s", output)
	}
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", source, err)
	}
	writeFile(t, destination, string(data))
	if err := os.Chmod(destination, 0o755); err != nil {
		t.Fatalf("Chmod %s: %v", destination, err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}
