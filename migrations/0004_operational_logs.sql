CREATE TABLE operational_logs (
  id bigserial PRIMARY KEY,
  source text NOT NULL DEFAULT '',
  category text NOT NULL CHECK (category IN ('feed', 'api', 'system')),
  level text NOT NULL CHECK (level IN ('info', 'warn', 'error')),
  message text NOT NULL CHECK (length(message) BETWEEN 1 AND 512),
  detail text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX operational_logs_created_at_idx
  ON operational_logs (created_at DESC, id DESC);

CREATE INDEX operational_logs_source_created_at_idx
  ON operational_logs (source, created_at DESC, id DESC)
  WHERE source <> '';
