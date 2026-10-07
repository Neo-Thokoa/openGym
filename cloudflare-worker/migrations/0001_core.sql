CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  session_version INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  admin INTEGER NOT NULL DEFAULT 0,
  last_pull INTEGER
);

CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  display_name TEXT,
  created_at TEXT NOT NULL,
  last_used TEXT
);
CREATE INDEX IF NOT EXISTS passkeys_user_idx ON passkeys(user_id);

CREATE TABLE IF NOT EXISTS states (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  document TEXT NOT NULL,
  rev INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges(expires_at);

CREATE TABLE IF NOT EXISTS device_link_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_link_user_idx ON device_link_codes(user_id);

CREATE TABLE IF NOT EXISTS pair_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pair_codes_user_idx ON pair_codes(user_id);

CREATE TABLE IF NOT EXISTS media (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  ext TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  unreferenced_at INTEGER,
  PRIMARY KEY (user_id, hash)
);
CREATE INDEX IF NOT EXISTS media_user_idx ON media(user_id);
