const {getDb} = require('./db');
const {newID} = require('./id');

// SELECTs alias id AS _id so every existing call site (controllers, views,
// req.user._id) keeps working unchanged -- this app's code was written
// against Mongoose's _id convention throughout.
const SELECT_COLUMNS = 'id AS _id, username, name, email, password_hash, created_at, updated_at';

function createUser({username, name, email, passwordHash}) {
  const id = newID();
  getDb().prepare(
      `INSERT INTO users (id, username, name, email, password_hash) VALUES (?, ?, ?, ?, ?)`,
  ).run(id, username, name, email, passwordHash);
  return id;
}

function getUserByUsername(username) {
  return getDb().prepare(`SELECT ${SELECT_COLUMNS} FROM users WHERE username = ?`).get(username);
}

function getUserById(id) {
  return getDb().prepare(`SELECT ${SELECT_COLUMNS} FROM users WHERE id = ?`).get(id);
}

function listUsers() {
  return getDb().prepare(`SELECT ${SELECT_COLUMNS} FROM users ORDER BY username`).all();
}

// vulnerability: mass assignment -- callers pass whatever fields the client
// sent, whitelisted only to real column names (not to the fields the
// caller is supposed to be allowed to touch). Mirrors
// insecureapplication-go/gallery-idp/db/users.go's UpdateUserFields.
const ALLOWED_FIELDS = {name: true, email: true, password_hash: true};

function updateUserFields(username, fields) {
  for (const [col, val] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS[col]) continue;
    getDb().prepare(`UPDATE users SET ${col} = ?, updated_at = datetime('now') WHERE username = ?`)
        .run(val, username);
  }
}

function deleteUser(username) {
  getDb().prepare(`DELETE FROM users WHERE username = ?`).run(username);
}

module.exports = {createUser, getUserByUsername, getUserById, listUsers, updateUserFields, deleteUser};
