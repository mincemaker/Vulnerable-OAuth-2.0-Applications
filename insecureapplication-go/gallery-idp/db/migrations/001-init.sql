-- Schema for gallery-idp. Deliberately vulnerable: see doc/OAuth2_PoC_Verification_Report.md
-- in the parent repo for the vulnerability classes this schema is designed to reproduce.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- vulnerability: no redirect_uris column. Clients CAN submit a redirectURIs
-- value on create/update, but it is never persisted -- mirrors the original
-- Mongoose Client schema, which likewise has no redirectURIs field.
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  name TEXT,
  client_secret TEXT NOT NULL, -- vulnerability: stored in plaintext
  trusted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- vulnerability: no expiry column, and rows are never deleted after use
-- (authorization codes are reusable and never expire).
CREATE TABLE IF NOT EXISTS authorization_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  redirect_uri TEXT,
  scope TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT,
  scope TEXT,
  expires_in INTEGER NOT NULL DEFAULT 3600,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scope TEXT,
  expires_in INTEGER NOT NULL DEFAULT 36000000,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL, -- vulnerability: raw client-supplied filename, no sanitization
  description TEXT,
  user_id TEXT NOT NULL,
  album TEXT NOT NULL DEFAULT 'default',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- vulnerability: name is globally unique, not scoped per-user
CREATE TABLE IF NOT EXISTS albums (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  user_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- cookie sessions + oauth2 "authorization in progress" transaction state,
-- combined into one table since both are keyed by the session cookie.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  pending_authz TEXT NOT NULL DEFAULT '{}', -- JSON: {txID: {client_id,redirect_uri,scope,state}}
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
