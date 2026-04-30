CREATE TABLE feed_source_status (
  source text PRIMARY KEY,
  last_success_at timestamptz,
  last_attempt_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  records_processed integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

