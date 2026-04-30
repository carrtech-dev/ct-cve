CREATE TABLE cve_records (
  cve_id text PRIMARY KEY,
  title text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  severity text NOT NULL DEFAULT 'unknown',
  cvss_score numeric(3,1),
  published_at timestamptz,
  modified_at timestamptz,
  rejected boolean NOT NULL DEFAULT false,
  known_exploited boolean NOT NULL DEFAULT false,
  kev_due_date date,
  kev_vendor_project text NOT NULL DEFAULT '',
  kev_product text NOT NULL DEFAULT '',
  kev_required_action text NOT NULL DEFAULT '',
  source text NOT NULL,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE affected_packages (
  id bigserial PRIMARY KEY,
  cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
  source text NOT NULL,
  distro_id text NOT NULL DEFAULT '',
  distro_version_id text NOT NULL DEFAULT '',
  distro_codename text NOT NULL DEFAULT '',
  package_name text NOT NULL,
  source_package_name text NOT NULL DEFAULT '',
  fixed_version text NOT NULL DEFAULT '',
  affected_versions text[] NOT NULL DEFAULT ARRAY[]::text[],
  repository text NOT NULL DEFAULT '',
  severity text NOT NULL DEFAULT 'unknown',
  package_state text NOT NULL DEFAULT '',
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX affected_packages_lookup_idx
  ON affected_packages (distro_id, distro_version_id, distro_codename, package_name);

CREATE TABLE integration_findings (
  id uuid PRIMARY KEY,
  org_id text NOT NULL,
  host_id text NOT NULL,
  package_id text NOT NULL,
  cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE RESTRICT,
  confidence text NOT NULL,
  reason text NOT NULL DEFAULT '',
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  resolved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, host_id, package_id, cve_id)
);

CREATE INDEX integration_findings_org_host_idx
  ON integration_findings (org_id, host_id, last_seen_at DESC);

