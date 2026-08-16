const {getDb} = require('./db');
const {orNull} = require('./id');

function scanClient(row) {
  if (!row) return null;
  return {...row, trusted: !!row.trusted};
}

// Mongoose's Boolean SchemaType cast the string "false" (what a urlencoded
// form body gives you for trusted=false) to the boolean false; plain JS
// truthiness does not ("false" is a non-empty string), so raw `val ? 1 : 0`
// would mark a client trusted=1 on exactly the input meant to keep it
// untrusted. This reproduces Mongoose's cast rather than JS truthiness.
function toBoolInt(val) {
  if (typeof val === 'string') {
    return (val !== '' && val !== 'false' && val !== '0') ? 1 : 0;
  }
  return val ? 1 : 0;
}

// redirectURI is intentionally accepted but discarded -- the original
// Mongoose Client schema has no redirectURIs field either, so a
// self-registered client's declared callback is never actually recorded or
// checked anywhere.
function createClient({clientId, name, clientSecret, trusted}) {
  getDb().prepare(
      `INSERT INTO clients (client_id, name, client_secret, trusted) VALUES (?, ?, ?, ?)`,
  ).run(clientId, orNull(name), clientSecret, toBoolInt(trusted));
}

function getClient(clientId) {
  return scanClient(getDb().prepare(`SELECT * FROM clients WHERE client_id = ?`).get(clientId));
}

function listClients() {
  return getDb().prepare(`SELECT * FROM clients ORDER BY client_id`).all().map(scanClient);
}

// vulnerability: no ownership/admin check performed by callers (IDOR --
// any logged-in user may edit any client). redirectURIs is accepted
// upstream but never lands in ALLOWED_FIELDS since the column doesn't exist.
const ALLOWED_FIELDS = {name: true, client_secret: true, trusted: true};

function updateClientFields(clientId, fields) {
  for (const [col, val] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS[col]) continue;
    const value = col === 'trusted' ? toBoolInt(val) : orNull(val);
    getDb().prepare(`UPDATE clients SET ${col} = ? WHERE client_id = ?`).run(value, clientId);
  }
}

function deleteClient(clientId) {
  getDb().prepare(`DELETE FROM clients WHERE client_id = ?`).run(clientId);
}

module.exports = {createClient, getClient, listClients, updateClientFields, deleteClient};
