CREATE TABLE gui_users (
  id bigserial PRIMARY KEY,
  username text NOT NULL UNIQUE CHECK (
    length(username) BETWEEN 3 AND 64
    AND username = lower(username)
    AND username ~ '^[a-z0-9._-]+$'
  ),
  password_hash text NOT NULL CHECK (length(password_hash) BETWEEN 20 AND 255),
  role text NOT NULL CHECK (role IN ('admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE gui_sessions (
  token_hash text PRIMARY KEY CHECK (length(token_hash) = 64),
  user_id bigint NOT NULL REFERENCES gui_users(id) ON DELETE CASCADE,
  csrf_token text NOT NULL CHECK (length(csrf_token) BETWEEN 32 AND 128),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX gui_sessions_user_id_idx
  ON gui_sessions (user_id);

CREATE INDEX gui_sessions_expires_at_idx
  ON gui_sessions (expires_at);
