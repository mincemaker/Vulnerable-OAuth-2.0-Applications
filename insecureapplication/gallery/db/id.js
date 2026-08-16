const crypto = require('crypto');

// Matches insecureapplication-go/gallery-idp/db/id.go's NewID(): a random
// hex string, not a Mongo ObjectID -- nothing in this app parses IDs as
// ObjectIDs, so there's no need to mimic that format.
function newID() {
  return crypto.randomBytes(12).toString('hex');
}

// node:sqlite only accepts `null` for a missing bind value -- `undefined`
// throws ("Provided value cannot be bound to SQLite parameter N"), unlike
// Mongoose, which silently tolerated an unset field on a non-required
// column. Shared by every db/*.js module that binds an optional value
// (scope/redirect_uri in oauth.js, description in albums.js/images.js,
// name in clients.js, etc).
function orNull(value) {
  return value === undefined ? null : value;
}

module.exports = {newID, orNull};
