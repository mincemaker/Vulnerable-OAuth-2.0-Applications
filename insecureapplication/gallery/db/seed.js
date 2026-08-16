// Populates the database with the same fixture data
// insecureapplication/mongo-seed/mongodbdata/gallery2 provided: two OAuth
// clients, one user ("koen"/"password"), two photos, two albums. Idempotent
// (safe to call on every startup) and, like the original mongo-seed
// container, honors CLIENT_ID/CLIENT_SECRET env vars for the PhotoPrint
// client's credentials. Mirrors insecureapplication-go/gallery-idp/db/seed.go.
const fs = require('fs');
const path = require('path');
const bcryptjs = require('bcryptjs');

const clients = require('./clients');
const users = require('./users');
const albumsDb = require('./albums');
const images = require('./images');
const {newID} = require('./id');

// clientId/clientSecret are whatever CLIENT_ID/CLIENT_SECRET currently
// resolve to (default "photoprint"/"secret" if unset). Seeding directly
// under that id -- rather than always seeding "photoprint" and separately
// trying to rename it -- means a restart with a changed CLIENT_ID just
// creates/updates the newly-named client in place; it can't collide with a
// stale row from a *previous* CLIENT_ID, since that row is never touched.
function seedClients(clientId, clientSecret) {
  if (!clients.getClient(clientId)) {
    clients.createClient({clientId, name: 'PhotoPrint', clientSecret, trusted: false});
  } else {
    clients.updateClientFields(clientId, {client_secret: clientSecret});
  }
  if (!clients.getClient('maliciousclient')) {
    clients.createClient({clientId: 'maliciousclient', name: 'maliciousclient', clientSecret: 'secret', trusted: false});
  }
}

function seedUser() {
  let user = users.getUserByUsername('koen');
  if (user) return user._id;
  const hash = bcryptjs.hashSync('password', 10);
  return users.createUser({username: 'koen', name: 'koen', email: 'koen@buyens.org', passwordHash: hash});
}

function seedAlbumsAndPhotos(userId) {
  for (const a of [
    {name: 'Leuven', description: 'Pictures From My University Town'},
    {name: 'default', description: 'Default Album'},
  ]) {
    if (!albumsDb.getAlbumByName(a.name)) {
      albumsDb.createAlbum({name: a.name, description: a.description, userId});
    }
  }

  if (images.listImagesByUser(userId).length > 0) return;
  for (const img of [
    {file: '7ac9eb7f-1de1-4c47-819f-f41591035479.jpg', desc: 'Kuleuven Bib'},
    {file: 'ab1dcbf9-69cd-4fb9-b9e6-ea3a01f992a0.jpg', desc: 'Arenberg Castle'},
  ]) {
    images.createImage({url: img.file, description: img.desc, userId, album: 'Leuven'});
  }
}

// Extracts the embedded seed photos into uploadsDir, skipping any that
// already exist there -- lets a fresh checkout bootstrap its own uploads
// directory. Mirrors gallery-idp's db.WriteSeedUploads.
function writeSeedUploads(uploadsDir) {
  fs.mkdirSync(uploadsDir, {recursive: true});
  const seedDir = path.join(__dirname, 'seedfiles');
  for (const file of fs.readdirSync(seedDir)) {
    const dest = path.join(uploadsDir, file);
    if (fs.existsSync(dest)) continue;
    fs.copyFileSync(path.join(seedDir, file), dest);
  }
}

function seed(uploadsDir) {
  writeSeedUploads(uploadsDir);
  seedClients(process.env.CLIENT_ID || 'photoprint', process.env.CLIENT_SECRET || 'secret');
  const koenID = seedUser();
  seedAlbumsAndPhotos(koenID);
}

module.exports = {seed};
