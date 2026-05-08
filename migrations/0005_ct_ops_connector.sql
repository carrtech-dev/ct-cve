CREATE TABLE ct_ops_hosts (
  org_id text NOT NULL,
  host_id text NOT NULL,
  agent_id text,
  hostname text NOT NULL,
  display_name text,
  os text,
  os_version text,
  arch text,
  ip_addresses jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'unknown',
  last_seen_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, host_id)
);

CREATE INDEX ct_ops_hosts_org_status_idx
  ON ct_ops_hosts (org_id, status);

CREATE TABLE ct_ops_software_packages (
  org_id text NOT NULL,
  package_id text NOT NULL,
  host_id text NOT NULL,
  name text NOT NULL,
  version text NOT NULL,
  architecture text,
  source text NOT NULL,
  fingerprint text NOT NULL DEFAULT '',
  distro_id text,
  distro_version_id text,
  distro_codename text,
  distro_id_like text[] NOT NULL DEFAULT ARRAY[]::text[],
  source_name text,
  source_version text,
  package_epoch text,
  package_release text,
  repository text,
  origin text,
  install_date timestamptz,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  removed_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, package_id)
);

CREATE INDEX ct_ops_packages_org_host_idx
  ON ct_ops_software_packages (org_id, host_id);

CREATE INDEX ct_ops_packages_match_idx
  ON ct_ops_software_packages (source, distro_id, distro_codename, source_name, name);

CREATE TABLE ct_ops_inventory_snapshots (
  org_id text NOT NULL,
  snapshot_id text NOT NULL,
  contract_version text NOT NULL,
  snapshot_type text NOT NULL,
  generated_at timestamptz NOT NULL,
  cursor_value text,
  hosts_accepted integer NOT NULL DEFAULT 0,
  packages_accepted integer NOT NULL DEFAULT 0,
  rows_rejected integer NOT NULL DEFAULT 0,
  response_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, snapshot_id)
);

CREATE TABLE ct_cve_service_nonces (
  token_id text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (token_id, nonce)
);

CREATE INDEX ct_cve_service_nonces_expires_at_idx
  ON ct_cve_service_nonces (expires_at);

CREATE TABLE ct_ops_connection_status (
  org_id text PRIMARY KEY,
  configured boolean NOT NULL DEFAULT true,
  enabled boolean NOT NULL DEFAULT true,
  last_inventory_push_at timestamptz,
  last_finding_ingest_at timestamptz,
  last_health_check_at timestamptz,
  last_error_code text NOT NULL DEFAULT '',
  last_error_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE integration_findings
  ADD COLUMN finding_id text NOT NULL DEFAULT '',
  ADD COLUMN package_name text NOT NULL DEFAULT '',
  ADD COLUMN installed_version text NOT NULL DEFAULT '',
  ADD COLUMN fixed_version text,
  ADD COLUMN source text NOT NULL DEFAULT '',
  ADD COLUMN severity text NOT NULL DEFAULT 'unknown',
  ADD COLUMN cvss_score numeric(3,1),
  ADD COLUMN known_exploited boolean NOT NULL DEFAULT false,
  ADD COLUMN metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb;
