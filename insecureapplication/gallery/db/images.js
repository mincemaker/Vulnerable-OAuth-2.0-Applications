const {getDb} = require('./db');
const {newID, orNull} = require('./id');

// alias id AS _id: photoscontroller.js and the .jade views were written
// against Mongoose's _id convention throughout.
const SELECT_COLUMNS = 'id AS _id, url, description, user_id, album, created_at, updated_at';

function createImage({url, description, userId, album}) {
  const id = newID();
  getDb().prepare(
      `INSERT INTO images (id, url, description, user_id, album) VALUES (?, ?, ?, ?, ?)`,
  ).run(id, url, orNull(description), userId, album || 'default');
  return id;
}

function getImage(id) {
  return getDb().prepare(`SELECT ${SELECT_COLUMNS} FROM images WHERE id = ?`).get(id);
}

function listImagesByUser(userId) {
  return getDb().prepare(`SELECT ${SELECT_COLUMNS} FROM images WHERE user_id = ? ORDER BY created_at`).all(userId);
}

// vulnerability: no ownership check performed by callers (IDOR).
const ALLOWED_FIELDS = {description: true, album: true, url: true};

function updateImageFields(id, fields) {
  for (const [col, val] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS[col]) continue;
    getDb().prepare(`UPDATE images SET ${col} = ?, updated_at = datetime('now') WHERE id = ?`).run(orNull(val), id);
  }
}

function deleteImage(id) {
  getDb().prepare(`DELETE FROM images WHERE id = ?`).run(id);
}

module.exports = {createImage, getImage, listImagesByUser, updateImageFields, deleteImage};
