CREATE TABLE feed_source_config (
  source text PRIMARY KEY CHECK (source IN ('nvd', 'cisa-kev')),
  enabled boolean NOT NULL,
  base_url text NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
  api_key text NOT NULL DEFAULT '',
  request_delay_ms integer CHECK (request_delay_ms IS NULL OR request_delay_ms > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
