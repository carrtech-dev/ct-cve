# CT-CVE

CT-CVE is the standalone CarrTech vulnerability service. It owns vulnerability
feed sync, CVE/advisory catalog storage, package matching, vulnerability
enrichment, and the CT Ops integration boundary.

This repository is being bootstrapped from the CT Ops migration plan. The first
increment provides:

- A Go service entrypoint with `/healthz`.
- Configuration through `CT_CVE_HTTP_ADDR` and `CT_CVE_DATABASE_URL`.
- Initial PostgreSQL schema for CVE records, affected packages, and integration
  findings.
- Extracted distro package version comparison and matching logic.
- Docker and Compose definitions for local development.
- GitHub Actions CI running the Go test suite.

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

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `CT_CVE_DATABASE_URL` | Yes | | PostgreSQL connection string for CT-CVE. |
| `CT_CVE_HTTP_ADDR` | No | `:8080` | HTTP bind address for the combined API/worker service. |

## Migration Status

This bootstrap does not yet include feed sync workers, API routes, auth, or the
standalone GUI. Those follow as separate migration PRs so the service can grow
behind a stable repository and CI baseline.

