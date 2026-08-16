// Opens the SQLite database (Node's built-in node:sqlite -- no npm
// dependency, no native build step, see
// insecureapplication-go/z-ai/gallery-sqlite-plan.md) and runs migrations.
const {DatabaseSync} = require('node:sqlite');
const fs = require('fs');
const path = require('path');

let db;

function open(dbPath) {
  db = new DatabaseSync(dbPath);
  db.exec('PRAGMA foreign_keys = ON');
  return db;
}

function runMigrations() {
  const dir = path.join(__dirname, 'migrations');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    db.exec(sql);
  }
}

function getDb() {
  if (!db) {
    throw new Error('database not opened -- call db.open() first');
  }
  return db;
}

module.exports = {open, runMigrations, getDb};
