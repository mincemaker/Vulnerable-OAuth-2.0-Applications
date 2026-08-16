const {getDb} = require('./db');
const {newID, orNull} = require('./id');

function createAlbum({name, description, userId}) {
  const id = newID();
  getDb().prepare(
      `INSERT INTO albums (id, name, description, user_id) VALUES (?, ?, ?, ?)`,
  ).run(id, name, orNull(description), userId);
  return id;
}

// vulnerability: name is globally unique, not scoped per-user (see
// migrations/001-init.sql).
function getAlbumByName(name) {
  return getDb().prepare(`SELECT * FROM albums WHERE name = ?`).get(name);
}

function listAlbumsByUser(userId) {
  return getDb().prepare(`SELECT * FROM albums WHERE user_id = ? ORDER BY name`).all(userId);
}

const ALLOWED_FIELDS = {description: true};

function updateAlbumFields(name, fields) {
  for (const [col, val] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS[col]) continue;
    getDb().prepare(`UPDATE albums SET ${col} = ?, updated_at = datetime('now') WHERE name = ?`).run(orNull(val), name);
  }
}

function deleteAlbum(name) {
  getDb().prepare(`DELETE FROM albums WHERE name = ?`).run(name);
}

module.exports = {createAlbum, getAlbumByName, listAlbumsByUser, updateAlbumFields, deleteAlbum};
