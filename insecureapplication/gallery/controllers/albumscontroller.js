const albums = require('../db/albums');
const util = require('./util');

/**
 * Gets a list of all albums of the logged in user
 * @param {*} req request
 * @param {*} res response
 * @return {*} returns the rendered result.
 */
function getAlbums(req, res) {
  return renderAlbums(req, res, req.user);
}

/**
 * Creates an album
 * @param {*} req request
 * @param {*} res response
 */
function createAlbum(req, res) {
  let name;
  if (req.params.name) {
    name = req.params.name;
  } else {
    name = req.body.name;
  }
  try {
    albums.createAlbum({name: name, description: req.body.description, userId: req.user._id});
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return renderAlbum2(req, res, albums.getAlbumByName(name));
}

/**
 * Renders an album
 * @param {*} req request
 * @param {*} res response
 */
function renderAlbum(req, res) {
  let album = req.params.name;
  let foundalbum = albums.getAlbumByName(album);
  if (foundalbum == null) {
    return util.renderError(req, res, 'This album does not exist.', 'error');
  }
  return renderAlbum2(req, res, foundalbum);
}

/**
 * Updates an album
 * @param {*} req request
 * @param {*} res response
 */
function updateAlbum(req, res) {
  let name = req.params.name;
  let description = req.body.description;

  try {
    albums.updateAlbumFields(name, {description: description});
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return util.renderMessage(req, res, null, 204);
}

/**
 * Deletes an album
 * @param {*} req request
 * @param {*} res response
 */
function deleteAlbum(req, res) {
  let name = req.params.name;
  try {
    albums.deleteAlbum(name);
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return util.renderMessage(req, res, 'Successfully Deleted.', 200);
}

/**
 * Renders a given album
 * @param {*} req request
 * @param {*} res response
 * @param {*} album album
 * @return {*} response of res.format
 */
function renderAlbum2(req, res, album) {
  let backURL = req.header('Referer') || '/';

  return res.format({
    // if accept: text/html render a page
    'text/html': function() {
      res.render('album', {
        album: album,
        basepath: util.getFullURL(),
        imagepath: 'image',
        backURL: backURL,
      });
    },
    // if json: render a json response
    'application/json': function() {
      res.status(200).send({album: album});
    },
    // other formats are not supported
    'default': function() {
      res.status(406).send('Not Acceptable');
    },
  });
}

/**
 * Renders an album for a given user
 * @param {*} req request
 * @param {*} res response
 * @param {*} user user
 */
function renderAlbums(req, res, user) {
  let backURL = req.header('Referer') || '/';
  if (!user) return util.renderError(req, res, 'No such user.', 'error');
  let userAlbums = albums.listAlbumsByUser(user._id);
  console.log('User:' + user.username);
  console.log('Albums:' + JSON.stringify(userAlbums));

  return res.format({
    // if accept: text/html render a page
    'text/html': function() {
      res.render('albums', {
        editable: true,
        albums: userAlbums,
        basepath: util.getFullURL(),
        imagepath: util.getImagePath(user.username),
        backURL: backURL,
      });
    },
    // if json: render a json response
    'application/json': function() {
      if (userAlbums) {
        res.status(200).send({albums: userAlbums});
      } else {
        res.status(404).send([]);
      }
    },
    // other formats are not supported
    'default': function() {
      res.status(406).send('Not Acceptable');
    },
  });
}

exports = module.exports = {
  getAlbums: getAlbums,
  updateAlbum: updateAlbum,
  deleteAlbum: deleteAlbum,
  renderAlbum: renderAlbum,
  renderAlbums: renderAlbums,
  createAlbum: createAlbum,
};
