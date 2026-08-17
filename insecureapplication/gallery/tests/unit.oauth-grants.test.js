// Unit tests for db/oauth.js's access-token-issuance behavior. Ported from
// the original Mongoose AccessToken model's mocha/chai/sinon suite
// (tests/models.accesstoken.test.js, requiring a models/accesstoken.js that
// no longer exists -- both were removed by the SQLite migration, see
// db/migrations/001-init.sql for the current schema). Node built-ins only
// (node:test, node:assert, node:sqlite) -- no devDependencies, matching the
// rest of this repo's test suites.
//
// Two of the six original cases don't carry over as-is:
//  - "invalid without token": access_tokens.token is a TEXT PRIMARY KEY
//    with no explicit NOT NULL -- SQLite's classic PK-doesn't-imply-NOT-NULL
//    quirk for non-INTEGER primary keys means inserting a null token
//    actually succeeds (the row is just permanently unreachable via
//    getAccessToken, since `WHERE token = ?` never matches NULL).
//    Documented below instead of asserted as a failure, since forcing the
//    old "must throw" behavior would mean changing the shared schema, out
//    of scope here.
//  - "invalid without user": access_tokens.user_id is deliberately nullable
//    now -- middlewares/auth.js's BearerStrategy branches on a null user_id
//    to authenticate the *client* rather than a user. This is an
//    intentional schema difference from the original Mongoose model, not a
//    regression, so it's ported as a positive case instead.

const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../db/db');
const oauth = require('../db/oauth');
const config = require('../config/config.json');

function freshDb() {
  db.open(':memory:');
  db.runMigrations();
}

test('an access token requires a client_id -- NOT NULL constraint failure', () => {
  freshDb();
  assert.throws(
      () => oauth.createAccessToken('grant1', null, 'user1', null),
      /NOT NULL constraint failed: access_tokens\.client_id/,
  );
});

test('an access token does not require a user_id (client-only tokens are valid)', () => {
  freshDb();
  assert.doesNotThrow(() => oauth.createAccessToken('grant2', 'client1', null, null));
  const issued = oauth.getAccessToken('grant2');
  assert.equal(issued.user_id, null);
});

test('a null token value is accepted by SQLite but is then unreachable via getAccessToken', () => {
  freshDb();
  assert.doesNotThrow(() => oauth.createAccessToken(null, 'client1', 'user1', null));
  assert.equal(oauth.getAccessToken(null), undefined,
      'a null-token row can never be looked back up -- WHERE token = ? does not match NULL');
});

test('an access token has a default expiry time when created', () => {
  freshDb();
  oauth.createAccessToken('grant3', 'client1', 'user1', null);
  const issued = oauth.getAccessToken('grant3');
  assert.equal(issued.expires_in, config.token.access.expires_in);
});

test('an access token has a creation date', () => {
  freshDb();
  const before = Date.now();
  oauth.createAccessToken('grant4', 'client1', 'user1', null);
  const issued = oauth.getAccessToken('grant4');
  assert.ok(issued.created_at, 'expected a created_at value');
  const createdAtMs = oauth.parseCreatedAt(issued.created_at) * 1000;
  assert.ok(createdAtMs >= before - 1000 && createdAtMs <= Date.now() + 1000,
      `created_at (${issued.created_at}) should be close to now`);
});

test('an access token expires once its expires_in window has passed', () => {
  freshDb();
  oauth.createAccessToken('grant5', 'client1', 'user1', null, 1); // expires_in=1s
  assert.equal(oauth.isExpired(oauth.getAccessToken('grant5')), false,
      'must not be expired immediately after creation');

  // Rewrite created_at into the past rather than sleeping the test.
  const past = new Date(Date.now() - 5000).toISOString().slice(0, 19).replace('T', ' ');
  db.getDb().prepare('UPDATE access_tokens SET created_at = ? WHERE token = ?').run(past, 'grant5');
  assert.equal(oauth.isExpired(oauth.getAccessToken('grant5')), true,
      'must be expired after expires_in has elapsed');
});
