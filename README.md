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
- Embedded database migrations applied on service startup.
- NVD and CISA KEV feed sync that persists CVE metadata, known-exploited
  indicators, and source status.
- Extracted distro package version comparison and matching logic.
- Docker and Compose definitions for local development.
- GitHub Actions CI running the Go test suite.
- Release automation that opens release-please PRs and publishes GHCR images
  when releases are created.
- A built-in operational status GUI, editable source configuration forms, and a
  JSON status endpoint with recent feed/API activity logs.
- A CT Ops connector API that accepts signed inventory snapshots, matches
  installed packages, and delivers signed finding batches back to CT Ops.

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

Open `http://localhost:8080/status` for the CT-CVE operational status page, or
read `http://localhost:8080/api/status` for the same source health and
configuration summary as JSON. The status surface is for feed configuration and
observability only; host findings and customer-facing vulnerability reporting
remain in CT Ops.

The status page can enable or disable the NVD and CISA KEV sources, change
their feed endpoints, adjust the NVD request delay, and set or clear the NVD
API key. Saved source settings are stored in the CT-CVE database and are applied
to the next scheduled feed sync cycle.

Recent feed sync outcomes and source configuration API changes are recorded as
operational logs and shown on the status page and JSON endpoint. Logs report
whether an NVD API key is configured but never include the key value.

CT Ops pushes inventory to CT-CVE at
`POST /api/v1/ct-ops/inventory-snapshots`. CT-CVE verifies the signed service
request, stores the org-scoped host and software inventory, immediately matches
active packages against the persisted vulnerability catalog, and posts finding
batches back to CT Ops at
`/api/integrations/ct-cve/v1/finding-batches`.

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
| `CT_CVE_FEED_SYNC_INTERVAL` | No | `6h` | Periodic feed refresh interval used by enabled feed sources. |
| `CT_CVE_FEED_SYNC_ON_STARTUP` | No | `true` | Runs an immediate feed sync when the service starts. |
| `CT_CVE_FEED_HTTP_TIMEOUT` | No | `30s` | Per-request timeout for vulnerability feed HTTP calls. |
| `CT_CVE_NVD_ENABLED` | No | `true` | Enables the NVD CVE source. |
| `CT_CVE_NVD_BASE_URL` | No | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE API endpoint. |
| `CT_CVE_NVD_API_KEY` | No | | Optional NVD API key. Store this as a secret in deployed environments. |
| `CT_CVE_NVD_REQUEST_DELAY` | No | `6s` without an API key, `600ms` with an API key | Minimum delay between NVD API requests. |
| `CT_CVE_CISA_KEV_ENABLED` | No | `true` | Enables the CISA Known Exploited Vulnerabilities source. |
| `CT_CVE_CISA_KEV_BASE_URL` | No | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA KEV JSON feed URL. |
| `CT_CVE_CT_OPS_CONNECTIONS` | No | `[]` | JSON array of CT Ops connector definitions with org-scoped inbound inventory tokens and outbound CT Ops callback token. |

The status page reports whether the NVD API key is configured, but it never
returns the key value in HTML or JSON responses.

Example CT Ops connector configuration:

```json
[
  {
    "name": "Primary CT Ops",
    "orgId": "org_123",
    "ctOpsBaseUrl": "https://ctops.example.com",
    "inventoryTokens": [
      {
        "id": "ctops-inventory",
        "secret": "replace-with-at-least-32-bytes-of-secret",
        "scopes": ["inventory:write", "connection:read"]
      }
    ],
    "ctOpsToken": {
      "id": "ctcve-outbound",
      "secret": "replace-with-at-least-32-bytes-of-secret",
      "scopes": ["findings:write", "connection:read"]
    }
  }
]
```

The same HMAC request-signing contract is used in both directions:
`Authorization: CT-ServiceToken <token-id>`, `X-CT-Timestamp`, `X-CT-Nonce`,
`X-CT-Content-SHA256`, and `X-CT-Signature: v1=<base64url-hmac-sha256>`.

## Migration Status

This bootstrap now includes feed sync workers for the NVD and CISA KEV catalogs,
including persistence of CVE metadata, known-exploited CVE metadata, and source
status, plus the first CT-CVE status GUI/API slice with editable source
configuration and feed/API activity logs. The first CT Ops connector path is
implemented for signed inventory ingestion, immediate matching, and signed
finding delivery. CT-CVE subscription status from CT Ops remains outstanding
migration work.
