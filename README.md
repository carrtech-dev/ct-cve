# CT-CVE

CT-CVE is the standalone CarrTech vulnerability service. It owns vulnerability
feed sync, CVE/advisory catalog storage, package matching, vulnerability
enrichment, and the CT Ops integration boundary.

This repository is being bootstrapped from the CT Ops migration plan. The first
increment provides:

- A Go service entrypoint with `/healthz`.
- Configuration for the service, feed sync cadence, feed HTTP client, NVD, and
  CISA KEV sources.
- Initial PostgreSQL schema for CVE records, affected packages, and integration
  findings.
- Extracted distro package version comparison and matching logic.
- Docker and Compose definitions for local development.
- GitHub Actions CI running the Go test suite.
- Release automation that opens release-please PRs and publishes GHCR images
  when releases are created.

## Local Development

Run the unit tests:

```sh
go test ./...
```

Start the service and database:

```sh
docker compose up --build
```

The service listens on `http://localhost:8080` by default.

## Container Images

Release-please manages CT-CVE GitHub releases from Conventional Commit history.
When a release is created from `main`, GitHub Actions builds the service image
from this repository and publishes it to GitHub Container Registry:

```sh
docker pull ghcr.io/carrtech-dev/ct-cve:v0.1.0
docker pull ghcr.io/carrtech-dev/ct-cve:latest
```

Use a versioned tag for deployments that need reproducible rollouts. The
`latest` tag is provided for local evaluation and follows the most recent
published release.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `CT_CVE_DATABASE_URL` | Yes | | PostgreSQL connection string for CT-CVE. |
| `CT_CVE_HTTP_ADDR` | No | `:8080` | HTTP bind address for the combined API/worker service. |
| `CT_CVE_FEED_SYNC_INTERVAL` | No | `6h` | Periodic feed refresh interval used by the feed worker once enabled. |
| `CT_CVE_FEED_HTTP_TIMEOUT` | No | `30s` | Per-request timeout for vulnerability feed HTTP calls. |
| `CT_CVE_NVD_ENABLED` | No | `true` | Enables the NVD CVE source. |
| `CT_CVE_NVD_BASE_URL` | No | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE API endpoint. |
| `CT_CVE_NVD_API_KEY` | No | | Optional NVD API key. Store this as a secret in deployed environments. |
| `CT_CVE_NVD_REQUEST_DELAY` | No | `6s` without an API key, `600ms` with an API key | Minimum delay between NVD API requests. |
| `CT_CVE_CISA_KEV_ENABLED` | No | `true` | Enables the CISA Known Exploited Vulnerabilities source. |
| `CT_CVE_CISA_KEV_BASE_URL` | No | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA KEV JSON feed URL. |

## Migration Status

This bootstrap does not yet include feed sync workers, API routes, auth, or the
standalone GUI. Feed source configuration is present so the feed sync workers can
be added behind a validated runtime contract in a later migration PR, while the
remaining service capabilities follow behind a stable repository and CI baseline.
