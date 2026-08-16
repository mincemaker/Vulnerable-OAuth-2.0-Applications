const {getDb} = require('./db');
const {orNull} = require('./id');
const config = require('../config/config');

// grantcode()/granttoken()/etc. generate codes and tokens as JS numbers
// (Math.floor(Math.random() * ...)), matching the original's
// Math.floor(...) values that Mongoose auto-stringified when saved to a
// String-typed field. node:sqlite's parameter binding isn't as forgiving:
// an integer-valued JS `number` can get bound as SQLite REAL rather than
// INTEGER, and a REAL coerced into one of these TEXT PRIMARY KEY columns
// stringifies with a trailing ".0" (e.g. "86907.0") instead of matching the
// plain-string "86907" that arrives when a client posts code=86907 in a
// token exchange. Coercing to String() at the DB boundary keeps every
// code/token column holding, and looked up by, the same plain-integer text
// regardless of whether the caller passed a JS number or string.
function id(value) {
  return value == null ? value : String(value);
}

// vulnerability: no expiry column, and rows are never deleted after use
// (see doc/OAuth2_PoC_Verification_Report.md PoC3/PoC5).
function createAuthCode(code, clientId, userId, redirectUri, scope) {
  getDb().prepare(
      `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope) VALUES (?, ?, ?, ?, ?)`,
  ).run(id(code), clientId, userId, orNull(redirectUri), orNull(scope));
}

// GetAuthCode looks a code up by code alone -- deliberately no client_id
// filter (PoC4: authorization code not bound to client).
function getAuthCode(code) {
  return getDb().prepare(`SELECT * FROM authorization_codes WHERE code = ?`).get(id(code));
}

function createAccessToken(token, clientId, userId, scope, expiresIn) {
  getDb().prepare(
      `INSERT INTO access_tokens (token, client_id, user_id, scope, expires_in) VALUES (?, ?, ?, ?, ?)`,
  ).run(id(token), clientId, userId || null, orNull(scope), expiresIn == null ? config.token.access.expires_in : expiresIn);
}

function getAccessToken(token) {
  return getDb().prepare(`SELECT * FROM access_tokens WHERE token = ?`).get(id(token));
}

function createRefreshToken(token, clientId, userId, scope, expiresIn) {
  getDb().prepare(
      `INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_in) VALUES (?, ?, ?, ?, ?)`,
  ).run(id(token), clientId, userId, orNull(scope), expiresIn == null ? config.token.refresh.expires_in : expiresIn);
}

// GetRefreshToken: deliberately no client_id filter (PoC6: refresh token
// not bound to client).
function getRefreshToken(token) {
  return getDb().prepare(`SELECT * FROM refresh_tokens WHERE token = ?`).get(id(token));
}

// SQLite's datetime('now') format ("YYYY-MM-DD HH:MM:SS", UTC, no
// timezone marker) isn't directly parseable by `new Date()` as UTC in every
// JS engine, so this is shared by isExpired() and tokeninfo().
function parseCreatedAt(createdAt) {
  return new Date(createdAt.replace(' ', 'T') + 'Z').getTime() / 1000;
}

// Matches accesstoken.js/refreshtoken.js's isExpired(): actually called by
// middlewares/auth.js's BearerStrategy (unlike gallery-idp's Go port, where
// the equivalent check is implemented but deliberately never wired up --
// this Node app's original code really does enforce it).
function isExpired(token) {
  return Date.now() / 1000 > parseCreatedAt(token.created_at) + token.expires_in;
}

module.exports = {
  createAuthCode, getAuthCode,
  createAccessToken, getAccessToken,
  createRefreshToken, getRefreshToken,
  isExpired, parseCreatedAt,
};
