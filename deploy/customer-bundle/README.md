# CT-CVE Customer Bundle

This bundle runs CT-CVE on a single host with Docker Compose.

## Requirements

- Docker Engine 24 or newer with the Compose plugin
- `openssl`
- `curl` and `unzip` for online upgrades

## First Start

```sh
unzip ct-cve-single.zip
cd ct-cve
./start.sh
```

On first run, `start.sh` creates `.env`, generates a database password, starts
PostgreSQL, starts CT-CVE, and waits for `/healthz`. CT-CVE applies embedded
database migrations automatically before the health check succeeds.

Open `http://localhost:8080/status` after startup. Change `CT_CVE_HTTP_PORT` in
`.env` if port 8080 is already in use.

## Upgrade

```sh
./upgrade.sh
```

The upgrade helper backs up local install files, downloads the latest bundle,
preserves `.env`, stops containers without deleting named volumes, installs the
new files, and starts CT-CVE. Use `./upgrade.sh --from-zip <path>` for a bundle
that was downloaded separately.
