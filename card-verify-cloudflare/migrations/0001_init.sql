CREATE TABLE IF NOT EXISTS cards (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'unused' CHECK (status IN ('unused', 'active', 'disabled')),
  bound_hwid TEXT,
  hwid_changed_at INTEGER,
  duration_seconds INTEGER,
  expires_at INTEGER,
  activated_at INTEGER,
  created_at INTEGER NOT NULL,
  note TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  card_id TEXT NOT NULL,
  hwid TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (card_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_card_heartbeat
  ON sessions(card_id, hwid);

CREATE INDEX IF NOT EXISTS idx_sessions_token
  ON sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_cards_created_at
  ON cards(created_at);
